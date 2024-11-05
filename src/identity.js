import { ed25519, x25519 } from "@noble/curves/ed25519";

import Constants from "./constants.js";
import Destination from "./destination.js";
import Cryptography from "./cryptography.js";
import Packet from "./packet.js";
import Transport from "./transport.js";
import Fernet from "./fernet.js";

class Identity {

    // X.25519 key size in bits. A complete key is the concatenation of a 256 bit encryption key, and a 256 bit signing key.
    static KEYSIZE_IN_BITS = 256 * 2;
    static KEYSIZE_IN_BYTES = this.KEYSIZE_IN_BITS / 8;

    // X.25519 ratchet key size in bits.
    static RATCHETSIZE_IN_BITS = 256;
    static RATCHETSIZE_IN_BYTES = this.RATCHETSIZE_IN_BITS / 8;

    // length of identity name hashes
    static NAME_HASH_LENGTH_IN_BITS = 80;
    static NAME_HASH_LENGTH_IN_BYTES = this.NAME_HASH_LENGTH_IN_BITS / 8;

    // Non-configurable constants
    // static FERNET_OVERHEAD           = RNS.Cryptography.Fernet.FERNET_OVERHEAD
    // static AES128_BLOCKSIZE          = 16          # In bytes
    // static HASHLENGTH                = 256         # In bits
    static SIGLENGTH_IN_BITS = this.KEYSIZE_IN_BITS;
    static SIGLENGTH_IN_BYTES = this.SIGLENGTH_IN_BITS / 8;

    constructor() {

        // keys
        this.publicKeyBytes = null;
        this.privateKeyBytes = null;
        this.signaturePublicKeyBytes = null;
        this.signaturePrivateKeyBytes = null;

        // hashes
        this.hash = null;
        this.hexhash = null;

    }

    static fromPublicKey(publicKeyBytes) {
        const identity = new Identity();
        identity.loadPublicKey(publicKeyBytes);
        return identity;
    }

    static fromPrivateKey(privateKeyBytes) {
        const identity = new Identity();
        identity.loadPrivateKey(privateKeyBytes);
        return identity;
    }

    static create() {

        const identity = new Identity();

        // generate public key and private key
        const privateKeyBytes = x25519.utils.randomPrivateKey();
        const publicKeyBytes = x25519.getPublicKey(privateKeyBytes);
        identity.publicKeyBytes = Buffer.from(publicKeyBytes);
        identity.privateKeyBytes = Buffer.from(privateKeyBytes);

        // generate signature public key and private key
        const signaturePrivateKeyBytes = ed25519.utils.randomPrivateKey();
        const signaturePublicKeyBytes = ed25519.getPublicKey(signaturePrivateKeyBytes);
        identity.signaturePublicKeyBytes = Buffer.from(signaturePublicKeyBytes);
        identity.signaturePrivateKeyBytes = Buffer.from(signaturePrivateKeyBytes);

        // update hashes
        identity.updateHashes();

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

    /**
     * Load a private key into the instance
     * @param {Buffer} privateKeyBytes - The public key as bytes.
     * @returns {boolean} True if the key was loaded, otherwise False.
     */
    loadPrivateKey(privateKeyBytes) {
        try {

            // private key bytes contains 2 keys
            const data = Array.from(privateKeyBytes);
            this.privateKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));
            this.signaturePrivateKeyBytes = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES / 2));

            // load public keys
            this.publicKeyBytes = Buffer.from(x25519.getPublicKey(this.privateKeyBytes));
            this.signaturePublicKeyBytes = Buffer.from(ed25519.getPublicKey(this.signaturePrivateKeyBytes));

            // update hashes
            this.updateHashes();

            return true;

        } catch(e) {
            console.log("Error while loading private key, the contained exception was", e);
            return false;
        }
    }

    getPublicKey() {
        return Buffer.concat([
            this.publicKeyBytes,
            this.signaturePublicKeyBytes,
        ]);
    }

    getPrivateKey() {
        return Buffer.concat([
            this.privateKeyBytes,
            this.signaturePrivateKeyBytes,
        ]);
    }

    updateHashes() {
        this.hash = Cryptography.truncatedHash(this.getPublicKey())
        this.hexhash = this.hash.toString("hex");
    }

    // Validates the signature of a signed message.
    validate(signature, data) {
        return ed25519.verify(signature, data, this.signaturePublicKeyBytes);
    }

    sign(data) {
        return Buffer.from(ed25519.sign(data, this.signaturePrivateKeyBytes));
    }

    /**
     * Encrypts information for the identity.
     * @param data
     * @returns {Buffer}
     */
    encrypt(data) {

        const ephemeralPrivateKeyBytes = Buffer.from(x25519.utils.randomPrivateKey());
        const ephemeralPublicKeyBytes = Buffer.from(x25519.getPublicKey(ephemeralPrivateKeyBytes));

        // todo ratchets
        // if ratchet != None:
        //     target_public_key = X25519PublicKey.from_public_bytes(ratchet)
        // else:
        //     target_public_key = self.pub

        const targetPublicKey = this.publicKeyBytes;

        // compute shared key
        const sharedKey = Buffer.from(x25519.getSharedSecret(ephemeralPrivateKeyBytes, targetPublicKey));

        // create derived key
        const derivedKey = Cryptography.hkdf(32, sharedKey, this.hash);

        // encrypt plaintext using fernet
        const fernet = new Fernet(derivedKey);
        const cipherText = fernet.encrypt(data);

        // create token
        const token = Buffer.concat([
            ephemeralPublicKeyBytes,
            cipherText,
        ]);

        return token;

    }

    /**
     * Decrypts information for the identity.
     * @param data
     * @returns {Buffer}
     */
    decrypt(data) {

        // parse peer public key and cipher text
        const peerPublicKeyBytes = data.slice(0, Identity.KEYSIZE_IN_BYTES / 2);
        const cipherText = data.slice(Identity.KEYSIZE_IN_BYTES / 2);

        // compute shared key
        const sharedKey = Buffer.from(x25519.getSharedSecret(this.privateKeyBytes, peerPublicKeyBytes));

        // create derived key
        const derivedKey = Cryptography.hkdf(32, sharedKey, this.hash);

        // decrypt ciphertext using fernet
        const fernet = new Fernet(derivedKey);
        return fernet.decrypt(cipherText);

    }

    static validateAnnounce(packet, onlyValidateSignature = false) {

        // packets types that aren't announces are not valid
        if(packet.packetType !== Packet.ANNOUNCE){
            return false;
        }

        // read data from packet
        const data = Array.from(packet.data);
        const publicKey = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES));
        const nameHash = Buffer.from(data.splice(0, Identity.NAME_HASH_LENGTH_IN_BYTES));
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
        const expectedHash = Cryptography.fullHash(hashMaterial).slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);

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

    prove(packetToProve) {

        // sign the hash of the packet to prove
        const signature = this.sign(packetToProve.packetHash);

        // determine if we should use implicit or explicit proof
        let proofData;
        if(packetToProve.destination.rns.shouldUseImplicitProof){
            proofData = signature;
        } else {
            proofData = Buffer.concat([
                packetToProve.packetHash,
                signature,
            ]);
        }

        // todo attached interface
        // todo reverse path table

        // create data packet
        const packet = new Packet();
        packet.hops = packetToProve.hops;
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.PROOF;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = null;
        packet.destinationHash = packetToProve.packetHash.slice(Constants.TRUNCATED_HASHLENGTH_IN_BYTES);
        packet.destinationType = Destination.SINGLE;
        packet.data = proofData;

        // pack packet
        const raw = packet.pack();

        // fixme: only send to receiving interface, and to reverse path table
        // send packet to all interfaces
        packetToProve.destination.rns.sendData(raw);

    }

}

export default Identity;
