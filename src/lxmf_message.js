const { unpack } = require('msgpackr');

class LXMessage {

    constructor() {
        this.source = null;
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
            const unpacked = unpack(packedPayload);
            const timestamp = unpacked[0];
            const title = unpacked[1].toString();
            const content = unpacked[2].toString();
            const fields = unpacked[3];

            // create and return lxmf message
            const lxmfMessage = new LXMessage();
            lxmfMessage.source = source;
            lxmfMessage.timestamp = timestamp;
            lxmfMessage.title = title;
            lxmfMessage.content = content;
            lxmfMessage.fields = fields;
            return lxmfMessage;

        } catch(e) {
            return null;
        }
    }

}

module.exports = LXMessage;
