const Cryptography = require("./cryptography");
const Constants = require("./constants");
const Packet = require("./packet");
const Transport = require("./transport");
const EventEmitter = require("./utils/events");

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
        this.nameHash = Cryptography.fullHash(nameWithoutIdentity).slice(0, Constants.IDENTITY_NAME_HASH_LENGTH_IN_BYTES);
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
        const nameHash = Cryptography.fullHash(fullName).slice(0, Constants.IDENTITY_NAME_HASH_LENGTH_IN_BYTES);

        let addrHashMaterial = nameHash;
        if(identity != null){
            addrHashMaterial = Buffer.concat([addrHashMaterial, identity.hash]);
        }

        return Cryptography.fullHash(addrHashMaterial).slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);

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

        const plaintext = this.decrypt(packet.data);

        this.emit("packet", {
            packet: packet,
            data: plaintext,
        });

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

}

module.exports = Destination;
