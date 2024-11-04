const { Packr } = require('msgpackr');
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

    static packer() {
        return new Packr({
            // we must disable conversion to javascript maps to avoid integer keys being converted to strings by js
            // using a Map instead of a JS object allows us to preserve sending an integer based key
            // this is needed otherwise msgunpack in LXMF router will use a string key, and looking up by integer key
            // will mean this field will not be found, even though it exists...
            mapsAsObjects: false,
        });
    }

    static fromBytes(data) {
        try {

            // parse data
            const source = data.slice(0, 16);
            const signature = data.slice(16, 16 + 64);
            const packedPayload = data.slice(16 + 64);

            // todo validate signature

            // unpack msgpack payload
            const unpacked = LXMessage.packer().unpack(packedPayload);
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

    pack(identity) {

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
        const packedPayload = LXMessage.packer().pack([
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
