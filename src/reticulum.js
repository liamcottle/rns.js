const EventEmitter = require("./utils/events");
const Destination = require("./destination");
const Packet = require("./packet");
const Announce = require("./announce");
const Identity = require("./identity");
const Link = require("./link");

class Reticulum extends EventEmitter {

    constructor() {

        super();

        this.shouldUseImplicitProof = true;

        this.interfaces = [];
        this.destinations = [];
        this.links = []; // a list of known links in any state
        this.packetHashList = []; // a list of packet hashes for duplicate detection

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

    addPacketToHashList(packetHash) {

        // todo auto truncate to max length, and save to persistent state?
        this.packetHashList.push(packetHash);

    }

    registerLink(link) {
        console.log(`Registering link ${link.hash.toString("hex")}`);
        this.links.push(link);
    }

    activateLink(link) {
        console.log(`Activating link ${link.hash.toString("hex")}`);
        if(this.links.includes(link) && link.status === Link.PENDING){
            link.status = Link.ACTIVE;
        }
    }

    onPacketReceived(packet, receivingInterface) {

        // handle received announces
        if(packet.packetType === Packet.ANNOUNCE){

            // todo if announce is for local destination, ignore it

            // handle received announce
            // const announce = Identity.validateAnnounce(packet);
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
                    if(link.status === Link.ACTIVE && link.hash.equals(packet.destinationHash)){
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


            console.log("link proof received", packet.data);

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

module.exports = Reticulum;
