import Cryptography from "./cryptography.js";
import MsgPack from "./msgpack.js";

class LXMessage {

    constructor() {
        this.sourceHash = null;
        this.destinationHash = null;
        this.timestamp = null;
        this.title = null;
        this.content = null;
        this.fields = null;
    }

    /**
     * Parse an LXMessage from the provided data.
     * @param data
     * @returns {null|LXMessage}
     */
    static fromBytes(data) {
        try {

            // parse data
            const source = data.slice(0, 16);
            const signature = data.slice(16, 16 + 64);
            const packedPayload = data.slice(16 + 64);

            // todo validate signature

            // unpack msgpack payload
            const unpacked = MsgPack.unpack(packedPayload);
            const timestamp = unpacked[0];
            const title = unpacked[1].toString();
            const content = unpacked[2].toString();
            const fields = unpacked[3];

            // create and return lxmf message
            const lxmfMessage = new LXMessage();
            lxmfMessage.sourceHash = source;
            lxmfMessage.timestamp = timestamp;
            lxmfMessage.title = title;
            lxmfMessage.content = content;
            lxmfMessage.fields = fields;
            return lxmfMessage;

        } catch(e) {
            console.log("failed to parse lxmf message from bytes", e);
            return null;
        }
    }

    /**
     * Packs the LXMessage to bytes for sending to a Destination.
     * @param identity the identity sending this message, which is used to sign it
     * @param opportunistic set to true if this message is being sent opportunistically
     * @returns {Buffer}
     */
    pack(identity, opportunistic = true) {

        // ensure fields is a Map, otherwise keys get converted from int to string...
        if(!(this.fields instanceof Map)){
            throw new Error("fields must be a Map instance");
        }

        // get current timestamp in seconds as float
        const timestampInSecondsAsFloat = Date.now() / 1000;

        // convert title and content to bytes
        const titleBytes = Buffer.from(this.title);
        const contentBytes = Buffer.from(this.content);

        // msgpack the payload
        const packedPayload = MsgPack.pack([
            timestampInSecondsAsFloat,
            titleBytes,
            contentBytes,
            this.fields,
        ]);

        // hashed part
        const hashedPart = Buffer.concat([
            this.destinationHash,
            this.sourceHash,
            packedPayload,
        ]);

        // hash the data
        const hash = Cryptography.fullHash(hashedPart);

        // signed part
        const signedPart = Buffer.concat([
            hashedPart,
            hash,
        ]);

        // sign the data
        const signature = identity.sign(signedPart);

        // packed
        const packed = Buffer.concat([
            opportunistic ? Buffer.alloc(0) : this.destinationHash, // opportunistic lxmf messages dont send destination in packed data
            this.sourceHash,
            signature,
            packedPayload,
        ]);

        return packed;

    }

}

export default LXMessage;
