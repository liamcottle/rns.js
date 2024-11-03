const {
    pack: msgpack,
    unpack: msgunpack,
} = require('msgpackr');
const Cryptography = require("./cryptography");

class LXMessage {

    constructor() {
        this.sourceHash = null;
        this.destinationHash = null;
        this.timestamp = null;
        this.title = null;
        this.content = null;
        this.fields = null;
    }

    static fromBytes(data) {
        try {

            // parse data
            const source = data.slice(0, 16);
            const signature = data.slice(16, 16 + 64);
            const packedPayload = data.slice(16 + 64);

            // todo validate signature

            // unpack msgpack payload
            const unpacked = msgunpack(packedPayload);
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
            return null;
        }
    }

    pack(identity) {

        // get current timestamp in seconds as float
        const timestampInSecondsAsFloat = Date.now() / 1000;

        // convert title and content to bytes
        const titleBytes = Buffer.from(this.title);
        const contentBytes = Buffer.from(this.content);

        // msgpack the payload
        const packedPayload = msgpack([
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
            // this.destinationHash, // self.__destination.hash (opportunistic lxmf messages dont send destination in packed data?)
            this.sourceHash,
            signature,
            packedPayload,
        ]);

        return packed;

    }

}

module.exports = LXMessage;
