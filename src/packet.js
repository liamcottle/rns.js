const Reticulum = require("./reticulum");
const Cryptography = require("./cryptography");

class Packet {

    // header types
    static HEADER_1 = 0x00; // Normal header format
    static HEADER_2 = 0x01; // Header format used for packets in transport
    // static HEADER_TYPES = [this.HEADER_1, this.HEADER_2];

    // packet types
    // static DATA = 0x00; // Data packets
    static ANNOUNCE = 0x01; // # Announces
    // static LINKREQUEST = 0x02; // Link requests
    // static PROOF = 0x03; // Proofs
    // static PACKET_TYPES = [this.DATA, this.ANNOUNCE, this.LINKREQUEST, this.PROOF];

    // context flag values
    static FLAG_SET = 0x01;
    static FLAG_UNSET = 0x00;

    // length of destination hashes
    static DESTINATION_HASH_LENGTH = Reticulum.TRUNCATED_HASHLENGTH_IN_BYTES;

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
            packet.packed = false;
            packet.updateHash();
        }

        return packet;

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
            hashablePart = Buffer.concat([hashablePart, this.raw.slice(Reticulum.TRUNCATED_HASHLENGTH_IN_BYTES + 2)]);
        } else {
            hashablePart = Buffer.concat([hashablePart, this.raw.slice(2)]);
        }

        return hashablePart;

    }

}

module.exports = Packet;
