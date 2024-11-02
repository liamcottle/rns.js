const crypto = require("crypto");

class Cryptography {

    static sha256(data) {
        return crypto.createHash('sha256').update(data).digest();
    }

}

module.exports = Cryptography;
