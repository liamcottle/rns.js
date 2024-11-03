const Reticulum = require("../src/reticulum");
const TCPClientInterface = require("../src/interfaces/tcp_client_interface");
const Identity = require("../src/identity");
const Destination = require("../src/destination");
const LXMessage = require("../src/lxmf_message");

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("localhost", "127.0.0.1", 4242));

// create test identity
// const identity = Identity.create();
const identity = Identity.fromPrivateKey(Buffer.from("9339cfce1fc75d4db4697cada620bb229de8a2164287c9302dbce840f38af39452f63722ef745fcef7bb3f90984b80c43a77ad1ff11127b88035b4ae4e670eaa", "hex"));

// create inbound lxmf destination
const localLxmfDestination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");

// listen for announces
const announcedDestinations = {};
rns.on("announce", (data) => {
    announcedDestinations[data.announce.destinationHash] = data.announce;
    console.log(`${data.announce.destinationHash.toString("hex")} is now ${data.hops} hops away on interface [${data.interface_name}] public key: ${data.announce.identity.getPublicKey().toString("hex")}`);
});

// listen for opportunistic lxmf packets
localLxmfDestination.on("packet", (event) => {

    // parse and log lxmf message
    const receivedLxmfMessage = LXMessage.fromBytes(event.data);
    if(!receivedLxmfMessage){
        return;
    }

    // prove that the packet was received
    event.packet.prove();

    // find identity for recipient destination hash
    const announce = announcedDestinations[receivedLxmfMessage.sourceHash];
    if(!announce){
        console.log("received message, but can't reply as no announce found");
        return;
    }

    // create recipient destination
    const recipientDestination = rns.registerDestination(announce.identity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

    // build reply with received content
    const replyLxmfMessage = new LXMessage();
    replyLxmfMessage.sourceHash = localLxmfDestination.hash;
    replyLxmfMessage.destinationHash = recipientDestination.hash;
    replyLxmfMessage.title = receivedLxmfMessage.title;
    replyLxmfMessage.content = receivedLxmfMessage.content;
    replyLxmfMessage.fields = receivedLxmfMessage.fields;

    // echo it back
    const packed = replyLxmfMessage.pack(identity);
    recipientDestination.send(packed);

});

// initial announce
setTimeout(() => {
    localLxmfDestination.announce(Buffer.from("@liamcottle/rns.js"));
}, 2000);
