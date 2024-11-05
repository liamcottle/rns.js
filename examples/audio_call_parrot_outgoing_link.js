import {
    Reticulum,
    Destination,
    Identity,
    Link,
    TCPClientInterface,
} from "../src/reticulum.js";

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("localhost", "127.0.0.1", 4242));

// macbook meshchat
const recipientIdentity = Identity.fromPublicKey(Buffer.from("dc59918b879177df2b17aed904c2fc2504657cde50156a8ef8e3202be9f3382076191725438483c4d5efdb1ac0ba5f76d15887a12ee0c0ab2ab8e8c23c8f77e3", "hex"));

// create outbound audio call destination
const audioCallDestination = rns.registerDestination(recipientIdentity, Destination.OUT, Destination.SINGLE, "call", "audio");

// listen for announces
const announcedDestinations = {};
rns.on("announce", (data) => {
    announcedDestinations[data.announce.destinationHash] = data.announce;
    console.log(`${data.announce.destinationHash.toString("hex")} is now ${data.hops} hops away on interface [${data.interface_name}] public key: ${data.announce.identity.getPublicKey().toString("hex")}`);
});

setTimeout(() => {

    // create a new link
    const link = new Link();

    // forward all packets received over the link back to the sender over the same link
    link.on("packet", (event) => {
        console.log("link packet received", event.packet.packetHash.toString("hex"));
        link.send(event.data);
    });

    // establish link to recipient audio call destination
    link.establish(audioCallDestination);

}, 2000);
