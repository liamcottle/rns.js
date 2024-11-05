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
        this.hash = null;
        this.publicKeyBytes = null;
        this.privateKeyBytes = null;
        this.signaturePublicKeyBytes = null;
        this.signaturePrivateKeyBytes = null;
    }

    /**
     * Load an Identity from the provided Public Key.
     * @param publicKeyBytes
     * @returns {Identity}
     */
    static fromPublicKey(publicKeyBytes) {
        const identity = new Identity();
        identity.loadPublicKey(publicKeyBytes);
        return identity;
    }

    /**
     * Load an Identity from the provided Private Key.
     * @param privateKeyBytes
     * @returns {Identity}
     */
    static fromPrivateKey(privateKeyBytes) {
        const identity = new Identity();
        identity.loadPrivateKey(privateKeyBytes);
        return identity;
    }

    /**
     * Create a new Identity with randomly generated keys.
     * @returns {Identity}
     */
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
     * Called internally to update the Identity hashes.
     */
    updateHashes() {
        this.hash = Cryptography.truncatedHash(this.getPublicKey());
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

    /**
     * Returns the Public Key for this Identity.
     * @returns {Buffer}
     */
    getPublicKey() {
        return Buffer.concat([
            this.publicKeyBytes,
            this.signaturePublicKeyBytes,
        ]);
    }

    /**
     * Returns the Private Key for this Identity.
     * @returns {Buffer}
     */
    getPrivateKey() {
        return Buffer.concat([
            this.privateKeyBytes,
            this.signaturePrivateKeyBytes,
        ]);
    }

    /**
     * Validates the signature of a signed message.
     * @param signature the signature to validate
     * @param data the data this signature is for
     * @returns {boolean}
     */
    validate(signature, data) {
        return ed25519.verify(signature, data, this.signaturePublicKeyBytes);
    }

    /**
     * Signs the provided data with this Identity's signature private key.
     * @param data
     * @returns {Buffer}
     */
    sign(data) {
        return Buffer.from(ed25519.sign(data, this.signaturePrivateKeyBytes));
    }

    /**
     * Encrypts information for the identity.
     * @param data the data to encrypt
     * @returns {Buffer}
     */
    encrypt(data) {

        // generate an ephemeral private key
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
     * @param data the data to decrypt
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

    /**
     * Prove that the provided Packet was received.
     * @param packetToProve
     */
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

        // create data packet
        const packet = new Packet();
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

        // send packet to attached interface
        packetToProve.destination.rns.sendData(raw, packetToProve.attachedInterface);

    }

}

export default Identity;
