const Cryptography = require("../cryptography");

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

module.exports = Interface;
