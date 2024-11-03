const Reticulum = require("./src/reticulum");
const TCPClientInterface = require("./src/interfaces/tcp_client_interface");
const Identity = require("./src/identity");
const Destination = require("./src/destination");

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("Home", "home.liamcottle.com", 4242));
// rns.addInterface(new TCPClientInterface("Server 1", "amsterdam.connect.reticulum.network", 4965));
// rns.addInterface(new TCPClientInterface("Server 2", "reticulum.betweentheborders.com", 4242));
// rns.addInterface(new TCPClientInterface("Server 3", "v0lttech.com", 4242));

// listen for announces
rns.on("announce", (data) => {
    console.log(`${data.announce.destinationHash.toString("hex")} is now ${data.hops} hops away on interface [${data.interface_name}]`);
});

// create test identity
// const identity = Identity.create();
const identity = Identity.fromPrivateKey(Buffer.from("9339cfce1fc75d4db4697cada620bb229de8a2164287c9302dbce840f38af39452f63722ef745fcef7bb3f90984b80c43a77ad1ff11127b88035b4ae4e670eaa", "hex"));

// create a destination
const destination = rns.registerDestination(identity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

setTimeout(() => {
    destination.announce(Buffer.from("@liamcottle/rns.js"));
}, 2000);
