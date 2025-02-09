import { Reticulum, TCPClientInterface } from "../src/reticulum.js";

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("Test Net", "amsterdam.connect.reticulum.network", 4965));
rns.addInterface(new TCPClientInterface("Between the Borders", "reticulum.betweentheborders.com", 4242));
rns.addInterface(new TCPClientInterface("V0ltTech", "v0lttech.com", 4242));

// listen for announces
rns.on("announce", (event) => {
    console.log(`Announce Received: ${event.announce.destinationHash.toString("hex")} is now ${event.hops} hops away on interface [${event.interface_name}]`);
});
