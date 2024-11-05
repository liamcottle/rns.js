import Identity from "./identity.js";
import Packet from "./packet.js";

class Announce {

    constructor() {
        this.destinationHash = null;
        this.identity = null;
        this.appData = null;
    }

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

            // create and return announce
            const announce = new Announce();
            announce.destinationHash = packet.destinationHash;
            announce.identity = announcedIdentity;
            announce.appData = appData;
            return announce;

        } catch(e) {
            return null;
        }
    }

}

export default Announce;
