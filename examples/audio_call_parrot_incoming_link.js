import {
    Reticulum,
    Destination,
    Identity,
    TCPClientInterface,
} from "../src/reticulum.js";

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("localhost", "127.0.0.1", 4242));

// create test identity
// const identity = Identity.create();
const identity = Identity.fromPrivateKey(Buffer.from("9339cfce1fc75d4db4697cada620bb229de8a2164287c9302dbce840f38af39452f63722ef745fcef7bb3f90984b80c43a77ad1ff11127b88035b4ae4e670eaa", "hex"));

// create inbound audio call destination
const audioCallDestination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "call", "audio");

// listen for announces
const announcedDestinations = {};
rns.on("announce", (data) => {
    announcedDestinations[data.announce.destinationHash] = data.announce;
    console.log(`${data.announce.destinationHash.toString("hex")} is now ${data.hops} hops away on interface [${data.interface_name}] public key: ${data.announce.identity.getPublicKey().toString("hex")}`);
});

// anounce self
setTimeout(() => {
    console.log(`announcing ${audioCallDestination.hash.toString("hex")}`);
    audioCallDestination.announce(Buffer.from("@liamcottle/rns.js"));
}, 2000);

// listen for incoming audio call link requests
audioCallDestination.on("link_request", (link) => {

    // log
    console.log("on link request", link);

    // log when link is established
    link.on("established", () => {
        console.log(`link established rtt: ${link.rtt}ms`);
    });

    // forward all packets received over the link back to the sender over the same link
    link.on("packet", (event) => {
        console.log("link packet received", event.packet.packetHash.toString("hex"));
        link.send(event.data);
    });

    // accept link from sender
    link.accept();

});
