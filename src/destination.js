import EventEmitter from "./utils/events.js";
import Constants from "./constants.js";
import Cryptography from "./cryptography.js";
import Packet from "./packet.js";
import Transport from "./transport.js";
import Identity from "./identity.js";

/**
 * Events emitted by a Destination
 * - link_request: When a request to establish a Link has been received.
 * - packet: When a Packet has been received over the Link.
 */
class Destination extends EventEmitter {

    // // constants
    static SINGLE = 0x00;
    // static GROUP = 0x01;
    // static PLAIN = 0x02;
    static LINK = 0x03;
    // static DESTINATION_TYPES = [this.SINGLE, this.GROUP, this.PLAIN, this.LINK];

    // directions
    static IN = 0x11;
    static OUT = 0x12;
    static DIRECTIONS = [this.IN, this.OUT];

    constructor(reticulum, identity, direction, type, appName, ...aspects) {

        super();

        this.rns = reticulum;
        this.identity = identity;
        this.direction = direction;
        this.type = type;
        this.appName = appName;
        this.aspects = aspects;

        this.name = Destination.expandName(identity, appName, ...aspects);
        const nameWithoutIdentity = Destination.expandName(null, appName, ...aspects);

        // generate the destination address hash
        this.hash = Destination.hash(this.identity, this.appName, ...aspects);
        this.nameHash = Cryptography.fullHash(nameWithoutIdentity).slice(0, Identity.NAME_HASH_LENGTH_IN_BYTES);
        this.hexhash = this.hash.toString("hex");

    }

    static expandName(identity, appName, ...aspects) {

        // Check input values and build name string
        if(appName.includes(".")){
            throw new Error("Dots can't be used in app names");
        }

        let name = appName;
        for(const aspect of aspects){
            if(aspect.includes(".")){
                throw new Error("Dots can't be used in aspects");
            }
            name += "." + aspect;
        }

        if(identity != null){
            name += "." + identity.hexhash;
        }

        return name;

    }

    static hash(identity, appName, ...aspects) {

        const fullName = Destination.expandName(null, appName, ...aspects);
        const nameHash = Cryptography.fullHash(fullName).slice(0, Identity.NAME_HASH_LENGTH_IN_BYTES);

        let addrHashMaterial = nameHash;
        if(identity != null){
            addrHashMaterial = Buffer.concat([addrHashMaterial, identity.hash]);
        }

        return Cryptography.fullHash(addrHashMaterial).slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);

    }

    encrypt(data) {

        // handle single destination type with known identity
        if(this.type === Destination.SINGLE && this.identity != null){
            // todo ratchets
            return this.identity.encrypt(data);
        }

    }

    decrypt(data) {

        // todo
        // if(this.type === Destination.PLAIN){
        //     return data;
        // }

        // handle single destination type with known identity
        if(this.type === Destination.SINGLE && this.identity != null){
            // todo ratchets
            return this.identity.decrypt(data);
        }

        throw new Error("Not Implemented");

    }

    onPacket(packet) {

        // set destination on packet so prove will have access to it
        packet.destination = this;

        // handle incoming link requests
        if(packet.packetType === Packet.LINKREQUEST){
            this.onIncomingLinkRequest(packet);
            return;
        }

        // decrypt packet data
        const plaintext = this.decrypt(packet.data);

        // handle incoming data
        if(packet.packetType === Packet.DATA){
            this.emit("packet", {
                packet: packet,
                data: plaintext,
            });
        }

    }

    onIncomingLinkRequest(packet) {

        console.log("incoming link request", packet);

        // todo allow destination to enable/disable incoming link requests

        // create link from link request
        const link = packet.destination.rns._createLink();
        if(!link.validateLinkRequest(packet)){
            return;
        }

        // fire link request event
        this.emit("link_request", link);

    }

    announce(appDataBytes = null) {

        // create random hash
        const randomHash = Buffer.concat([
            Cryptography.getRandomHash().slice(0, 5), // 5 random bytes
            Cryptography.getRandomHash().slice(0, 5), // fixme: this should be current timestamp in seconds, as 5 bytes, but it doesn't seem to be used for anything else
        ]);

        // todo: handle ratchets
        let ratchet = Buffer.alloc(0);
        // if (this.ratchets !== null) {
        //     this.rotateRatchets();
        //     ratchet = this.identity.getRatchetPublicBytes(this.ratchets[0]);  // Placeholder for ratchet public bytes method
        //     this.identity.rememberRatchet(this.hash, ratchet);  // Placeholder to remember ratchet
        // }

        // create signed data
        let signedData = Buffer.concat([
            this.hash,
            this.identity.getPublicKey(),
            this.nameHash,
            randomHash,
            ratchet,
        ]);

        // add app data to signed data if provided
        if(appDataBytes !== null){
            signedData = Buffer.concat([
                signedData,
                appDataBytes,
            ]);
        }

        // sign the data
        const signature = this.identity.sign(signedData);

        // create announce data
        let announceData = Buffer.concat([
            this.identity.getPublicKey(),
            this.nameHash,
            randomHash,
            ratchet,
            signature,
        ]);

        // add app data to announce data if provided
        if(appDataBytes !== null){
            announceData = Buffer.concat([
                announceData,
                appDataBytes,
            ]);
        }

        // set context flag if ratchet provided
        let contextFlag = Packet.FLAG_UNSET;
        if(ratchet.length > 0){
            contextFlag = Packet.FLAG_SET;
        }

        // create announce packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.ANNOUNCE;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = contextFlag;
        packet.destinationHash = this.hash;
        packet.destinationType = this.type;
        packet.data = announceData;

        // pack packet
        const raw = packet.pack();

        // send packet to all interfaces
        this.rns.sendData(raw);

    }

    send(data) {

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = this.type;
        packet.data = data;

        // // force using a transport node
        // packet.headerType = Packet.HEADER_2;
        // packet.transportType = Transport.TRANSPORT;
        // packet.transportId = Buffer.from("25ffd99be40b112a3a11294badae6d8f", "hex"); // Windows PC MeshChat

        // pack packet
        const raw = packet.pack();

        // send packet to all interfaces
        this.rns.sendData(raw);

    }

}

export default Destination;
