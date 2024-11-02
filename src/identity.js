const { ed25519 } = require("@noble/curves/ed25519");
const Cryptography = require("./cryptography");
const Packet = require("./packet");
const Reticulum = require("./reticulum");

class Identity {

    // X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
    static KEYSIZE_IN_BITS = 256 * 2;
    static KEYSIZE_IN_BYTES = this.KEYSIZE_IN_BITS / 8;

    // X.25519 ratchet key size in bits.
    static RATCHETSIZE_IN_BITS = 256;
    static RATCHETSIZE_IN_BYTES = this.RATCHETSIZE_IN_BITS / 8;

    // Non-configurable constants
    // static FERNET_OVERHEAD           = RNS.Cryptography.Fernet.FERNET_OVERHEAD
    // static AES128_BLOCKSIZE          = 16          # In bytes
    // static HASHLENGTH                = 256         # In bits
    static SIGLENGTH_IN_BITS = this.KEYSIZE_IN_BITS;
    static SIGLENGTH_IN_BYTES = this.SIGLENGTH_IN_BITS / 8;

    static NAME_HASH_LENGTH_IN_BITS = 80;
    static NAME_HASH_LENGTH_IN_BYTES = this.NAME_HASH_LENGTH_IN_BITS / 8;

    constructor() {

        // public keys
        this.publicKeyBytes = null;
        this.signaturePublicKeyBytes = null;

        // hashes
        this.hash = null;
        this.hexhash = null;

    }

    static fromPublicKey(publicKeyBytes) {
        const identity = new Identity();
        identity.loadPublicKey(publicKeyBytes);
        return identity;
    }

    /**
     * Load a public key into the instance
     * @param {Buffer} publicKeyBytes - The public key as bytes.
     * @returns {boolean} True if the key was loaded, otherwise False.
     */
    loadPublicKey(publicKeyBytes) {
        try {
            // public key bytes contains 2 keys
            const data = Array.from(publicKeyBytes);
            this.publicKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));
            this.signaturePublicKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));
            this.updateHashes();
            return true;
        } catch(e) {
            console.log("Error while loading public key, the contained exception was", e);
            return false;
        }
    }

    getPublicKey() {
        return Buffer.concat([
            this.publicKeyBytes,
            this.signaturePublicKeyBytes,
        ]);
    }

    updateHashes() {
        this.hash = Identity.truncatedHash(this.getPublicKey())
        this.hexhash = this.hash.toString("hex");
    }

    // Validates the signature of a signed message.
    validate(signature, data) {
        return ed25519.verify(signature, data, this.signaturePublicKeyBytes);
    }

    /**
     * Get a SHA-256 hash of passed data.
     * @param data
     * @returns {Buffer}
     */
    static fullHash(data) {
        return Cryptography.sha256(data);
    }

    /**
     * Get a truncated SHA-256 hash of passed data.
     * @param data
     * @returns {Buffer}
     */
    static truncatedHash(data) {
        return this.fullHash(data).slice(0, Reticulum.TRUNCATED_HASHLENGTH_IN_BYTES);
    }

    static validateAnnounce(packet, onlyValidateSignature = false) {

        // packets types that aren't announces are not valid
        if(packet.packetType !== Packet.ANNOUNCE){
            return false;
        }

        // read data from packet
        const data = Array.from(packet.data);
        const publicKey = Buffer.from(data.splice(0, this.KEYSIZE_IN_BYTES));
        const nameHash = Buffer.from(data.splice(0, this.NAME_HASH_LENGTH_IN_BYTES));
        const randomHash = Buffer.from(data.splice(0, 10)); // 5 bytes random, 5 bytes time

        // read ratchet bytes if context flag is set
        let ratchet = Buffer.from([]);
        if(packet.contextFlag === Packet.FLAG_SET){
            ratchet = Buffer.from(data.splice(0, this.RATCHETSIZE_IN_BYTES));
        }

        // read signature and use remaining bytes as app data
        const signature = Buffer.from(data.splice(0, this.SIGLENGTH_IN_BYTES));
        const appData = Buffer.from(data);

        // get data that should be signed
        const signedData = Buffer.concat([
            packet.destinationHash,
            publicKey,
            nameHash,
            randomHash,
            ratchet,
            appData,
        ]);

        // load identity from public key
        const announcedIdentity = Identity.fromPublicKey(publicKey);

        // validate signature of announce with announced identity
        if(!announcedIdentity.validate(signature, signedData)){
            console.log(`Received invalid announce for ${packet.destinationHash.toString("hex")}: Invalid signature.`)
            return false;
        }

        // check if we only want to validate the signature
        if(onlyValidateSignature){
            return true;
        }

        // get hash material and expected hash
        const hashMaterial = Buffer.concat([nameHash, announcedIdentity.hash]);
        const expectedHash = Identity.fullHash(hashMaterial).slice(0, Reticulum.TRUNCATED_HASHLENGTH_IN_BYTES);

        // check if destination hash matches expected hash
        if(!packet.destinationHash.equals(expectedHash)){
            console.log(`Received invalid announce for ${packet.destinationHash.toString("hex")}: Destination mismatch.`);
            return false;
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

        return true;

    }

}

module.exports = Identity;
