const crypto = require("crypto");
const Constants = require("./constants");

class Cryptography {

    static sha256(data) {
        return crypto.createHash('sha256').update(data).digest();
    }

    /**
     * Get a SHA-256 hash of passed data.
     * @param data
     * @returns {Buffer}
     */
    static fullHash(data) {
        return this.sha256(data);
    }

    /**
     * Get a truncated SHA-256 hash of passed data.
     * @param data
     * @returns {Buffer}
     */
    static truncatedHash(data) {
        return this.fullHash(data).slice(0, Constants.TRUNCATED_HASHLENGTH_IN_BYTES);
    }

    /**
     * Get a random SHA-256 hash.
     * Returns a truncated SHA-256 hash of random data as bytes.
     */
    static getRandomHash() {
        const randomBytes = crypto.randomBytes(Constants.TRUNCATED_HASHLENGTH_IN_BYTES);
        return this.truncatedHash(randomBytes);
    }

}

module.exports = Cryptography;
