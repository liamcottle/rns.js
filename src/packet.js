const Constants = require("./constants");
const Cryptography = require("./cryptography");

class Packet {

    // header types
    static HEADER_1 = 0x00; // Normal header format
    static HEADER_2 = 0x01; // Header format used for packets in transport
    // static HEADER_TYPES = [this.HEADER_1, this.HEADER_2];

    // packet types
    static DATA = 0x00; // Data packets
    static ANNOUNCE = 0x01; // # Announces
    // static LINKREQUEST = 0x02; // Link requests
    // static PROOF = 0x03; // Proofs
    // static PACKET_TYPES = [this.DATA, this.ANNOUNCE, this.LINKREQUEST, this.PROOF];

    // Packet context types
    static NONE           = 0x00; // Generic data packet
    // static RESOURCE       = 0x01; // Packet is part of a resource
    // static RESOURCE_ADV   = 0x02; // Packet is a resource advertisement
    // static RESOURCE_REQ   = 0x03; // Packet is a resource part request
    // static RESOURCE_HMU   = 0x04; // Packet is a resource hashmap update
    // static RESOURCE_PRF   = 0x05; // Packet is a resource proof
    // static RESOURCE_ICL   = 0x06; // Packet is a resource initiator cancel message
    // static RESOURCE_RCL   = 0x07; // Packet is a resource receiver cancel message
    // static CACHE_REQUEST  = 0x08; // Packet is a cache request
    // static REQUEST        = 0x09; // Packet is a request
    // static RESPONSE       = 0x0A; // Packet is a response to a request
    // static PATH_RESPONSE  = 0x0B; // Packet is a response to a path request
    // static COMMAND        = 0x0C; // Packet is a command
    // static COMMAND_STATUS = 0x0D; // Packet is a status of an executed command
    // static CHANNEL        = 0x0E; // Packet contains link channel data
    // static KEEPALIVE      = 0xFA; // Packet is a keepalive packet
    // static LINKIDENTIFY   = 0xFB; // Packet is a link peer identification proof
    // static LINKCLOSE      = 0xFC; // Packet is a link close message
    // static LINKPROOF      = 0xFD; // Packet is a link packet proof
    // static LRRTT          = 0xFE; // Packet is a link request round-trip time measurement
    static LRPROOF        = 0xFF; // Packet is a link request proof

    // context flag values
    static FLAG_SET = 0x01;
    static FLAG_UNSET = 0x00;

    // length of destination hashes
    static DESTINATION_HASH_LENGTH = Constants.TRUNCATED_HASHLENGTH_IN_BYTES;

    constructor() {

        this.raw = null;

        this.flags = null;
        this.hops = null;
        this.headerType = null;
        this.contextFlag = null;
        this.transportType = null;
        this.destinationType = null;
        this.packetType = null;
        this.transportId = null;
        this.destinationHash = null;
        this.context = null;
        this.data = null;

        this.packetHash = null;

        this.destination = null;

    }

    static fromBytes(bytes) {

        // create new packet
        const packet = new Packet();
        packet.raw = bytes;

        // read flags and hops
        packet.flags = bytes[0];
        packet.hops = bytes[1];

        // parse flags
        packet.headerType = (packet.flags & 0b01000000) >> 6;
        packet.contextFlag = (packet.flags & 0b00100000) >> 5;
        packet.transportType = (packet.flags & 0b00010000) >> 4;
        packet.destinationType = (packet.flags & 0b00001100) >> 2;
        packet.packetType = (packet.flags & 0b00000011);

        // todo cleanup
        if(packet.headerType === Packet.HEADER_2){
            packet.transportId = bytes.slice(2, Packet.DESTINATION_HASH_LENGTH + 2); // [2:DST_LEN+2]
            packet.destinationHash = bytes.slice(Packet.DESTINATION_HASH_LENGTH + 2, 2 * Packet.DESTINATION_HASH_LENGTH + 2); // [DST_LEN+2:2*DST_LEN+2]
            // fixme: context ord?
            // const context = this.ord(raw.slice(2*DST_LEN+2, 2*DST_LEN+3)); // [2*DST_LEN+2:2*DST_LEN+3])
            packet.context = bytes.slice(2 * Packet.DESTINATION_HASH_LENGTH + 2, 2 * Packet.DESTINATION_HASH_LENGTH + 3); // [2*DST_LEN+2:2*DST_LEN+3])
            packet.data = bytes.slice(2 * Packet.DESTINATION_HASH_LENGTH + 3); // [2*DST_LEN+3:]
        } else {
            packet.transportId = null;
            packet.destinationHash = bytes.slice(2, Packet.DESTINATION_HASH_LENGTH + 2); // [2:DST_LEN+2]
            // fixme: context ord?
            // const context = this.ord(raw.slice(DST_LEN+2, DST_LEN+3)); // [DST_LEN+2:DST_LEN+3])
            packet.context = bytes.slice(Packet.DESTINATION_HASH_LENGTH + 2, Packet.DESTINATION_HASH_LENGTH + 3); // [DST_LEN+2:DST_LEN+3])
            packet.data = bytes.slice(Packet.DESTINATION_HASH_LENGTH + 3); // [DST_LEN+3:]
        }

        // update hash
        packet.updateHash();

        return packet;

    }

    static packFlags(context, headerType, contextFlag, transportType, destinationType, packetType) {

        // // force destination type for link request proof
        // if(context === Packet.LRPROOF){
        //     destinationType = Destination.LINK;
        // }

        // pack flags
        return (headerType << 6)
            | (contextFlag << 5)
            | (transportType << 4)
            | (destinationType << 2)
            | packetType;

    }

    static uint8ToBytes(flags) {
        const flagsBuffer = Buffer.alloc(1);
        flagsBuffer.writeUInt8(flags, 0);
        return flagsBuffer;
    }

    pack() {

        // set hop count
        const hops = 0;

        // pack flags
        const flags = Packet.packFlags(this.context, this.headerType, this.contextFlag, this.transportType, this.destinationType, this.packetType);

        // standard header
        let header = Buffer.concat([
            Packet.uint8ToBytes(flags),
            Packet.uint8ToBytes(hops),
        ]);

        // determine cipher text
        let ciphertext;
        if(this.packetType === Packet.ANNOUNCE){
            // add plaintext announce data
            ciphertext = this.data;
        } else {
            // encrypt all other packets with the destination identity
            ciphertext = this.destination.encrypt(this.data);
        }

        // create raw packet data based on header type
        if(this.headerType === Packet.HEADER_1){
            this.raw = Buffer.concat([
                header,
                this.destinationHash,
                Buffer.from([this.context]),
                ciphertext,
            ]);
        } else if(this.headerType === Packet.HEADER_2) {
            this.raw = Buffer.concat([
                header,
                this.transportId,
                this.destinationHash,
                Buffer.from([this.context]),
                ciphertext,
            ]);
        }

        // todo
        // if (this.raw.length > this.MTU) {
        //     throw new Error(`Packet size of ${this.raw.length} exceeds MTU of ${this.MTU} bytes`);
        // }

        // update hash
        this.updateHash();

        return this.raw;

    }

    getHash() {
        // return Identity.fullHash(this.getHashablePart());
        return Cryptography.sha256(this.getHashablePart());
    }

    updateHash() {
        this.packetHash = this.getHash();
    }

    getHashablePart() {

        // fixme implement properly

        // destination type and packet type from flags?
        let hashablePart = Buffer.from([this.raw[0] & 0b00001111]);

        if(this.headerType === Packet.HEADER_2){
            hashablePart = Buffer.concat([hashablePart, this.raw.slice(Constants.TRUNCATED_HASHLENGTH_IN_BYTES + 2)]);
        } else {
            hashablePart = Buffer.concat([hashablePart, this.raw.slice(2)]);
        }

        return hashablePart;

    }

}

module.exports = Packet;
