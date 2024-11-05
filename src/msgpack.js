import { Packr } from "msgpackr";

class MsgPack {

    static packer() {
        return new Packr({
            // we must disable conversion to javascript maps to avoid integer keys being converted to strings by js
            // using a Map instead of a JS object allows us to preserve sending an integer based key
            // this is needed otherwise msgunpack in LXMF router will use a string key, and looking up by integer key
            // will mean this field will not be found, even though it exists...
            mapsAsObjects: false,
        });
    }

    static pack(data) {
        return this.packer().pack(data);
    }

    static unpack(data) {
        return this.packer().unpack(data);
    }

}

export default MsgPack;
