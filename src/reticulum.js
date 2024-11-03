const EventEmitter = require("./utils/events");
const Destination = require("./destination");
const Packet = require("./packet");
const Announce = require("./announce");

class Reticulum extends EventEmitter {

    constructor() {
        super();
        this.interfaces = [];
        this.destinations = [];
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

            // pass data packets to their intended destination
            for(const destination of this.destinations){
                if(destination.hash.equals(packet.destinationHash)){
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

module.exports = Reticulum;
