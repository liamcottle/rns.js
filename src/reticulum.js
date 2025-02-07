import EventEmitter from "./utils/events.js";
import Announce from "./announce.js";
import Destination from "./destination.js";
import Identity from "./identity.js";
import Link from "./link.js";
import Packet from "./packet.js";
// import TCPClientInterface from "./interfaces/tcp_client_interface.js";
import WebsocketClientInterface from "./interfaces/websocket_client_interface.js";
import LXMessage from "./lxmf/lxmf_message.js";

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

    /**
     * Add an Interface that can be used to send and receive data.
     * @param iface
     */
    addInterface(iface) {

        // tell interface which rns instance to use
        iface.setReticulumInstance(this);

        // add to interfaces list
        this.interfaces.push(iface);

        // auto connect
        iface.connect();

    }

    /**
     * Registers a Destination
     * Example: rns.registerDestination(identity, Destination.IN, Destination.SINGLE, "lxmf", "delivery");
     * @param identity the identity that owns this destination, for inbound this is your identity, for outbound this is the recipients identity
     * @param direction the direction of this destination, either "Destination.IN" or "Destination.OUT"
     * @param type the type of this destination, only "Destination.SINGLE" and "Destination.LINK" are supported for now
     * @param appName the app name, for example: "lxmf"
     * @param aspects the aspects for this destination, for example "delivery"
     * @returns {Destination}
     */
    registerDestination(identity, direction, type, appName, ...aspects) {

        // create destination
        const destination = new Destination(this, identity, direction, type, appName, ...aspects);

        // add to destinations list
        this.destinations.push(destination);

        return destination;

    }

    /**
     * Send data to all interfaces.
     * todo: allow passing in a specific interface to send to, instead of all interfaces
     * @param data the data to send
     * @param outboundInterface the interface to send via. if not provided data is sent to all interfaces
     */
    sendData(data, outboundInterface = null) {

        // if outbound interface provided, send via that instead of all interfaces
        if(outboundInterface != null){
            outboundInterface.sendData(data);
            return;
        }

        // fallback to sending via all interfaces
        for(const iface of this.interfaces){
            iface.sendData(data);
        }

    }

    /**
     * Called internally to register a Link.
     * @param link
     */
    registerLink(link) {
        console.log(`Registering link ${link.hash.toString("hex")}`);
        this.links.push(link);
    }

    /**
     * Called internally to activate a Link.
     * @param link
     */
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

    /**
     * Called internally when an Announce is received.
     * @param announce
     */
    onAnnounceReceived(announce) {
        this.emit("announce", announce);
    }

    /**
     * Called internally when a Packet has been received by an Interface.
     * @param packet the packet that was received
     * @param receivingInterface the interface the packet was received on
     */
    onPacketReceived(packet, receivingInterface) {

        // set receiving interface on the packet
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

            // todo implement

            // if (Identity.knownDestinations[destinationHash] && !publicKey.equals(Identity.knownDestinations[destinationHash][2])) {
            //     RNS.log("Received announce with valid signature and destination hash, but announced public key does not match already known public key.", RNS.LOG_CRITICAL);
            //     return false;
            // }
            //
            // RNS.Identity.remember(packet.getHash(), destinationHash, publicKey, appData);
            //
            // let signalStr = "";
            // if (packet.rssi !== undefined || packet.snr !== undefined) {
            //     signalStr += " [";
            //     if (packet.rssi !== undefined) signalStr += `RSSI ${packet.rssi}dBm`;
            //     if (packet.rssi !== undefined && packet.snr !== undefined) signalStr += ", ";
            //     if (packet.snr !== undefined) signalStr += `SNR ${packet.snr}dB`;
            //     signalStr += "]";
            // }
            //
            // if (packet.transportId) {
            //     RNS.log(`Valid announce for ${RNS.prettyHexRep(destinationHash)} ${packet.hops} hops away, received via ${RNS.prettyHexRep(packet.transportId)} on ${packet.receivingInterface}${signalStr}`, RNS.LOG_EXTREME);
            // } else {
            //     RNS.log(`Valid announce for ${RNS.prettyHexRep(destinationHash)} ${packet.hops} hops away, received on ${packet.receivingInterface}${signalStr}`, RNS.LOG_EXTREME);
            // }
            //
            // if (ratchet) {
            //     Identity._rememberRatchet(destinationHash, ratchet);
            // }
            //

            // pass announce to rns
            this.onAnnounceReceived({
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

}

export {
    Reticulum,
    Destination,
    Identity,
    Link,
    Packet,
    // TCPClientInterface,
    WebsocketClientInterface,
    LXMessage,
};
