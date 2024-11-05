class PKCS7 {

    static BLOCKSIZE = 16;

    static pad(data, bs = PKCS7.BLOCKSIZE) {
        const l = data.length;
        const n = bs - (l % bs);
        const padding = Buffer.alloc(n, n);
        return Buffer.concat([data, padding]);
    }

    static unpad(data, bs = PKCS7.BLOCKSIZE) {
        const l = data.length;
        const n = data[l - 1];
        if(n > bs){
            throw new Error(`Cannot unpad, invalid padding length of ${n} bytes`);
        } else {
            return data.slice(0, l - n);
        }
    }

}

export default PKCS7;
