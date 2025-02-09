import Cryptography from "../cryptography.js";
import MsgPack from "../msgpack.js";

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

            // no data provided, unable to parse
            if(data == null || data.length === 0){
                return null;
            }

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
        return Buffer.concat([
            opportunistic ? Buffer.alloc(0) : this.destinationHash, // opportunistic lxmf messages dont send destination in packed data
            this.sourceHash,
            signature,
            packedPayload,
        ]);

    }

    /**
     * Packs the LXMessage to an encrypted lxm:// uri that can be ingested by the destination.
     * The lxm uri could be encoded as a QR code and scanned by Sideband.
     * @param senderIdentity the identity sending this message, which is used to sign it
     * @param destinationIdentity the identity this message is being sent to, which is used to encrypt it
     * @returns {string} an lxm:// uri with the encrypted message data in url safe base64
     */
    toLxmUri(senderIdentity, destinationIdentity) {

        // pack this lxmf message
        const packed = this.pack(senderIdentity, false);
        const destinationHash = packed.slice(0, 16);
        const packedWithoutDestinationHash = packed.slice(16);

        // encrypt packed data: sourceHash + signature + packedPayload
        const encryptedData = destinationIdentity.encrypt(packedWithoutDestinationHash);

        // prepare data that will be base64 encoded
        const data = Buffer.concat([
            destinationHash,
            encryptedData,
        ]);

        // convert raw data buffer to url safe base64
        const base64EncodedBuffer = data.toString("base64")
            .replace(/\+/g, '-') // convert '+' to '-'
            .replace(/\//g, '_') // convert '/' to '_'
            .replace(/=+$/, ''); // remove trailing '='

        // format as lxm:// uri
        return `lxm://${base64EncodedBuffer}`;

    }

}

export default LXMessage;
