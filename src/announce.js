import Identity from "./identity.js";
import Packet from "./packet.js";
import Cryptography from "./cryptography.js";
import Constants from "./constants.js";

class Announce {

    constructor() {
        this.destinationHash = null;
        this.identity = null;
        this.appData = null;
    }

    /**
     * Parse and validate an Announce from the provided Packet.
     * @param packet
     * @returns {Announce|null}
     */
    static fromPacket(packet) {
        try {

            // packets types that aren't announces are not valid
            if(packet.packetType !== Packet.ANNOUNCE){
                return null;
            }

            // read data from packet
            const data = Array.from(packet.data);
            const publicKey = Buffer.from(data.splice(0, Identity.KEYSIZE_IN_BYTES));
            const nameHash = Buffer.from(data.splice(0, Identity.NAME_HASH_LENGTH_IN_BYTES));
            const randomHash = Buffer.from(data.splice(0, 10)); // 5 bytes random, 5 bytes time

            // read ratchet bytes if context flag is set
            let ratchet = Buffer.from([]);
            if(packet.contextFlag === Packet.FLAG_SET){
                ratchet = Buffer.from(data.splice(0, Identity.RATCHETSIZE_IN_BYTES));
            }

            // read signature and use remaining bytes as app data
            const signature = Buffer.from(data.splice(0, Identity.SIGLENGTH_IN_BYTES));
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
                return null;
            }

            // get hash material and expected hash
            const hashMaterial = Buffer.concat([nameHash, announcedIdentity.hash]);
            const expectedHash = Cryptography.fullHash(hashMaterial).slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);

            // check if destination hash matches expected hash
            if(!packet.destinationHash.equals(expectedHash)){
                console.log(`Received invalid announce for ${packet.destinationHash.toString("hex")}: Destination mismatch.`);
                return null;
            }

            // create and return announce
            const announce = new Announce();
            announce.destinationHash = packet.destinationHash;
            announce.identity = announcedIdentity;
            announce.appData = appData;
            announce.transportId = packet.transportId; // fixme: temporarily saved on the announce for now
            return announce;

        } catch(e) {
            console.log("failed to parse and validate announce", e);
            return null;
        }
    }

}

export default Announce;
