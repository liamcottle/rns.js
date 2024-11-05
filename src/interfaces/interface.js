import Cryptography from "../cryptography.js";

class Interface {

    constructor(name) {
        this.rns = null;
        this.name = name;
        this.hash = this.getHash();
    }

    setReticulumInstance(rns) {
        this.rns = rns;
    }

    getHash() {
        return Cryptography.sha256(this.name);
    }

}

export default Interface;
