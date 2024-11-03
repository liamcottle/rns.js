const Reticulum = require("./src/reticulum");
const TCPClientInterface = require("./src/interfaces/tcp_client_interface");
const Identity = require("./src/identity");
const Destination = require("./src/destination");
const LXMessage = require("./src/lxmf_message");

// create rns instance
const rns = new Reticulum();

// add interfaces
// rns.addInterface(new TCPClientInterface("localhost", "127.0.0.1", 4242));
rns.addInterface(new TCPClientInterface("Home", "home.liamcottle.com", 4242));
// rns.addInterface(new TCPClientInterface("Server 1", "amsterdam.connect.reticulum.network", 4965));
// rns.addInterface(new TCPClientInterface("Server 2", "reticulum.betweentheborders.com", 4242));
// rns.addInterface(new TCPClientInterface("Server 3", "v0lttech.com", 4242));

// listen for announces
rns.on("announce", (data) => {
    console.log(`${data.announce.destinationHash.toString("hex")} is now ${data.hops} hops away on interface [${data.interface_name}] public key: ${data.announce.identity.getPublicKey().toString("hex")}`);
});

// create test identity
// const identity = Identity.create();
const identity = Identity.fromPrivateKey(Buffer.from("9339cfce1fc75d4db4697cada620bb229de8a2164287c9302dbce840f38af39452f63722ef745fcef7bb3f90984b80c43a77ad1ff11127b88035b4ae4e670eaa", "hex"));

// create a destination
const destination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");

// listen for opportunistic lxmf packets
destination.on("packet", (event) => {

    // parse and log lxmf message
    const lxmfMessage = LXMessage.fromBytes(event.data);
    console.log(lxmfMessage);

    // prove that the packet was received
    event.packet.prove();

});

// setTimeout(() => {
//     destination.announce(Buffer.from("@liamcottle/rns.js"));
// }, 2000);

// macbook meshchat
// const recipientIdentity = Identity.fromPublicKey(Buffer.from("dc59918b879177df2b17aed904c2fc2504657cde50156a8ef8e3202be9f3382076191725438483c4d5efdb1ac0ba5f76d15887a12ee0c0ab2ab8e8c23c8f77e3", "hex"));

// windows pc
const recipientIdentity = Identity.fromPublicKey(Buffer.from("8f895047d2c2f78ac3f54bbfec83d847a9115cf734ccab35dec01359732a894ce43d9fc4a65551e80a5a5b52d4c965c3a1d9c81b9d2f9ae4bb35af14020251f0", "hex"));
const recipientDestination = rns.registerDestination(recipientIdentity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

setTimeout(() => {

    // destination.announce(Buffer.from("@liamcottle/rns.js"));

    const lxmfMessage = new LXMessage();
    lxmfMessage.sourceHash = destination.hash;
    lxmfMessage.destinationHash = recipientDestination.hash;
    lxmfMessage.title = "";
    lxmfMessage.content = "hello from rns.js"
    lxmfMessage.fields = {};
    const packed = lxmfMessage.pack(identity);

    recipientDestination.send(packed);

}, 2000);
