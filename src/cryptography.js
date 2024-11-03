const crypto = require("crypto");
const Constants = require("./constants");

class Cryptography {

    static sha256(data) {
        return crypto.createHash('sha256').update(data).digest();
    }

    static hmacSha256(key, data) {
        return crypto.createHmac('sha256', key).update(data).digest();
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

    static hkdf(length, deriveFrom, salt = null, context = Buffer.alloc(0)) {

        // Length of SHA-256 hash in bytes
        const hashLength = 32;

        if(typeof length !== 'number' || length < 1){
            throw new Error("Invalid output key length");
        }

        if(!deriveFrom || deriveFrom.length === 0){
            throw new Error("Cannot derive key from empty input material");
        }

        // Default salt to a zeroed buffer of hash length if not provided
        salt = salt || Buffer.alloc(hashLength, 0);

        // Step 1: Extract a pseudorandom key
        const pseudorandomKey = this.hmacSha256(salt, deriveFrom);

        // Step 2: Expand the pseudorandom key
        let block = Buffer.alloc(0);
        let derived = Buffer.alloc(0);

        for(let i = 0; i < Math.ceil(length / hashLength); i++){
            block = this.hmacSha256(pseudorandomKey, Buffer.concat([block, context, Buffer.from([i + 1])]));
            derived = Buffer.concat([derived, block]);
        }

        return derived.slice(0, length);

    }

}

module.exports = Cryptography;
