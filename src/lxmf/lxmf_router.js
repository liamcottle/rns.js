import {Destination, LXMessage} from "../reticulum.js";
import EventEmitter from "../utils/events.js";
import Packet from "../packet.js";

class LXMRouter extends EventEmitter {

    constructor(rns, identity) {

        super();

        this.rns = rns;
        this.identity = identity;

        // register lxmf.delivery destination
        this.destination = rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");

        // listen for incoming packets
        this.destination.on("packet", (event) => {

            // parse and log lxmf message
            const receivedLxmfMessage = LXMessage.fromBytes(event.data);
            if(!receivedLxmfMessage){
                return;
            }

            // todo remove log, and mark the lxmessage object as being received opportunistically
            console.log("received opportunistic lxmf message", receivedLxmfMessage);

            // prove that the packet was received
            event.packet.prove();

            // fire callback
            this.emit("message", receivedLxmfMessage);

        });

        // listen for link requests for receiving direct lxmf messages
        this.destination.on("link_request", (link) => {

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

                // todo remove log, and mark the lxmessage object as being received over a direct link
                console.log("received direct lxmf message", receivedLxmfMessage);

                // fire callback
                this.emit("message", receivedLxmfMessage);

            });

            // accept link from sender
            link.accept();

        });

    }

    announce(displayName) {
        console.log("announcing lxmf destination", this.destination.hash.toString("hex"));
        // fixme: this is using the old format, need to update to new format with stamp cost
        this.destination.announce(Buffer.from(displayName));
    }

}

export default LXMRouter;
