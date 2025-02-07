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

    /**
     * Send data to from this interface.
     * This method should be implemented by subclasses.
     * @param data the data to send
     */
    sendData(data) {
        throw new Error("sendData should be implemented by Interface subclasses!");
    }

}

export default Interface;
