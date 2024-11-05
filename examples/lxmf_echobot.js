import {
    Reticulum,
    Destination,
    Identity,
    TCPClientInterface,
    LXMessage,
    Packet,
} from "../src/reticulum.js";

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

// initial announce
setTimeout(() => {
    console.log("announcing lxmf destination", localLxmfDestination.hash.toString("hex"));
    localLxmfDestination.announce(Buffer.from("@liamcottle/rns.js"));
}, 2000);

// listen for opportunistic lxmf packets
localLxmfDestination.on("packet", (event) => {

    // parse and log lxmf message
    const receivedLxmfMessage = LXMessage.fromBytes(event.data);
    if(!receivedLxmfMessage){
        return;
    }

    console.log("received opportunistic lxmf message", receivedLxmfMessage);

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

// listen for link requests for receiving direct lxmf messages
localLxmfDestination.on("link_request", (link) => {

    // log
    console.log("on link request", link);

    // log when link is established
    link.on("established", () => {
        console.log(`link established rtt: ${link.rtt}ms`);
    });

    // handle packet received over link
    link.on("packet", (event) => {

        console.log("link packet received", event);

        // parse destination hash and lxmf message bytes from link packet
        const data = Array.from(event.data);
        const destinationHash = Buffer.from(data.splice(0, Packet.DESTINATION_HASH_LENGTH));
        const lxmfMessageBytes = Buffer.from(data); // remaining data

        // parse and log lxmf message
        const receivedLxmfMessage = LXMessage.fromBytes(lxmfMessageBytes);
        if(!receivedLxmfMessage){
            return;
        }

        // prove that the packet was received
        link.proveLinkPacket(event.packet);

        console.log("received direct lxmf message", receivedLxmfMessage);

        // build reply with received content
        const replyLxmfMessage = new LXMessage();
        replyLxmfMessage.sourceHash = localLxmfDestination.hash;
        replyLxmfMessage.destinationHash = receivedLxmfMessage.sourceHash;
        replyLxmfMessage.title = receivedLxmfMessage.title;
        replyLxmfMessage.content = receivedLxmfMessage.content;
        replyLxmfMessage.fields = receivedLxmfMessage.fields;

        // echo it back over the link
        const packed = replyLxmfMessage.pack(identity, false);
        link.send(packed);

    });

    // accept link from sender
    link.accept();

});
