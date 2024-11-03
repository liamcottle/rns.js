const crypto = require("crypto");
const PKCS7 = require("./pkcs7");

class Fernet {

    static FERNET_OVERHEAD = 48;

    constructor(key) {
        if (!key) {
            throw new Error("Token key cannot be null");
        }

        if (key.length !== 32) {
            throw new Error(`Token key must be 32 bytes, not ${key.length}`);
        }

        this._signing_key = key.slice(0, 16);
        this._encryption_key = key.slice(16);
    }

    static generateKey() {
        return crypto.randomBytes(32);
    }

    verifyHmac(token) {

        if(token.length <= 32){
            throw new Error(`Cannot verify HMAC on token of only ${token.length} bytes`);
        }

        const receivedHmac = token.slice(-32);
        const dataToSign = token.slice(0, -32);
        const expectedHmac = crypto.createHmac('sha256', this._signing_key).update(dataToSign).digest();

        return receivedHmac.equals(expectedHmac);

    }

    encrypt(data) {


        if(!Buffer.isBuffer(data)){
            throw new TypeError("Token plaintext input must be a Buffer");
        }

        const iv = crypto.randomBytes(16);
        const paddedData = PKCS7.pad(data);

        const cipher = crypto.createCipheriv('aes-128-cbc', this._encryption_key, iv);
        let ciphertext = cipher.update(paddedData);
        ciphertext = Buffer.concat([ciphertext, cipher.final()]);

        const signedParts = Buffer.concat([iv, ciphertext]);
        const hmac = crypto.createHmac('sha256', this._signing_key).update(signedParts).digest();

        return Buffer.concat([signedParts, hmac]);

    }

    decrypt(token) {

        // ensure token is a buffer
        if(!Buffer.isBuffer(token)){
            throw new TypeError("Token must be a Buffer");
        }

        // verify token hmac
        if(!this.verifyHmac(token)){
            throw new Error("Token HMAC was invalid");
        }

        const iv = token.slice(0, 16);
        const ciphertext = token.slice(16, -32);

        const decipher = crypto.createDecipheriv('aes-128-cbc', this._encryption_key, iv);
        let plaintext = decipher.update(ciphertext);
        plaintext = Buffer.concat([plaintext, decipher.final()]);

        // fixme unpadding seems to not be working as expected...
        // return PKCS7.unpad(plaintext);
        return plaintext;

    }

}

module.exports = Fernet;
