import EventEmitter from "./utils/events.js";
import Announce from "./announce.js";
import Destination from "./destination.js";
import Identity from "./identity.js";
import Link from "./link.js";
import Packet from "./packet.js";
import TCPClientInterface from "./interfaces/tcp_client_interface.js";
import LXMessage from "./lxmf_message.js";

/**
 * Events emitted by Reticulum
 * - announce: When an Announce has been received.
 */
class Reticulum extends EventEmitter {

    constructor() {

        super();

        this.shouldUseImplicitProof = true;

        this.interfaces = [];
        this.destinations = [];
        this.links = []; // a list of known links in any state

    }

    addInterface(iface) {

        // tell interface which rns instance to use
        iface.setReticulumInstance(this);

        // add to interfaces list
        this.interfaces.push(iface);

        // auto connect
        iface.connect();

    }

    onAnnounce(announce) {
        this.emit("announce", announce);
    }

    sendData(data) {
        for(const iface of this.interfaces){
            iface.sendData(data);
        }
    }

    registerLink(link) {
        console.log(`Registering link ${link.hash.toString("hex")}`);
        this.links.push(link);
    }

    activateLink(link) {
        console.log(`Activating link ${link.hash.toString("hex")}`);
        if(this.links.includes(link) && link.status === Link.PENDING){
            link.status = Link.ACTIVE;
            link.activatedAt = Date.now();
        }
    }

    /**
     * Returns true if the provided destinationHash is a local destination.
     * i.e if it has been registered with a direction of "IN".
     * @param destinationHash
     * @returns {boolean}
     */
    isLocalDestination(destinationHash) {
        return this.destinations.find((destination) => destination.hash.equals(destinationHash) && destination.direction === Destination.IN) != null;
    }

    onPacketReceived(packet, receivingInterface) {

        // set receiving interface
        packet.receivingInterface = receivingInterface;

        // handle received announces
        if(packet.packetType === Packet.ANNOUNCE){

            // if announce is for local destination, ignore it
            if(this.isLocalDestination(packet.destinationHash)){
                return;
            }

            // parse and validate received announce
            const announce = Announce.fromPacket(packet);
            if(!announce){
                return;
            }

            // pass announce to rns
            this.onAnnounce({
                announce: announce,
                hops: packet.hops,
                interface_name: receivingInterface.name,
                interface_hash: receivingInterface.hash,
            });

        } else if(packet.packetType === Packet.DATA) {
            if(packet.destinationType === Destination.LINK){
                // pass data packets to their intended links
                for(const link of this.links){
                    if(link.hash.equals(packet.destinationHash)){
                        link.onPacket(packet);
                    }
                }
            } else {
                // pass data packets to their intended destination
                for(const destination of this.destinations){
                    if(destination.hash.equals(packet.destinationHash)){
                        destination.onPacket(packet);
                    }
                }
            }
        } else if(packet.packetType === Packet.PROOF && packet.context === Packet.LRPROOF) {

            // ensure link proof data size is as expected
            if(packet.data.length !== Identity.SIGLENGTH_IN_BYTES + Link.ECPUBSIZE / 2){
                console.log(`Invalid link request proof in transport for link ${packet.destinationHash.toString("hex")}, dropping proof.`);
                return;
            }

            // find pending link for received link proof
            const pendingLink = this.links.find((link) => link.status === Link.PENDING && link.hash.equals(packet.destinationHash));
            if(!pendingLink){
                console.log("pending link not found for received link proof");
                return;
            }

            // todo drop packet if not expected hops, or not unknown max hops...
            // if packet.hops == link.expected_hops or link.expected_hops == RNS.Transport.PATHFINDER_M:

            // todo Add this packet to the filter hashlist if we have determined that it's actually destined for this system, and then validate the proof

            // remember packet hash so we can discard it later if seen again
            // todo this.addPacketToHashList(packet.packetHash);

            // validate proof
            pendingLink.validateProof(packet);

        } else if(packet.packetType === Packet.LINKREQUEST) {

            // pass link request packets to their intended destination
            for(const destination of this.destinations){
                if(destination.hash.equals(packet.destinationHash) && destination.type === packet.destinationType){
                    destination.onPacket(packet);
                }
            }

        }

    }

    registerDestination(identity, direction, type, appName, ...aspects) {

        // create destination
        const destination = new Destination(this, identity, direction, type, appName, ...aspects);

        // add to destinations list
        this.destinations.push(destination);

        return destination;

    }

}

export {
    Reticulum,
    Destination,
    Identity,
    Link,
    Packet,
    TCPClientInterface,
    LXMessage,
};
