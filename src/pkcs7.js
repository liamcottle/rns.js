class PKCS7 {

    static BLOCKSIZE = 16;

    static pad(data) {
        const paddingLength = PKCS7.BLOCKSIZE - (data.length % PKCS7.BLOCKSIZE);
        const padding = Buffer.alloc(paddingLength, paddingLength);
        return Buffer.concat([data, padding]);
    }

    static unpad(padded) {
        return padded.subarray(0, padded.length - padded[padded.length - 1]);
    }

}

module.exports = PKCS7;
