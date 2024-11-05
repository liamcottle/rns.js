class HDLC {

    static FLAG = 0x7E;
    static ESC = 0x7D;
    static ESC_MASK = 0x20;

    static escape(data) {

        let escapedData = Buffer.alloc(0);
        for(const byte of data){
            if(byte === HDLC.FLAG){
                escapedData = Buffer.concat([escapedData, Buffer.from([HDLC.ESC, HDLC.FLAG ^ HDLC.ESC_MASK])]);
            } else if(byte === HDLC.ESC){
                escapedData = Buffer.concat([escapedData, Buffer.from([HDLC.ESC, HDLC.ESC ^ HDLC.ESC_MASK])]);
            } else {
                escapedData = Buffer.concat([escapedData, Buffer.from([byte])]);
            }
        }

        return escapedData;

    }

    static unescape(data) {

        let unescapedData = Buffer.alloc(0);

        let i = 0;
        while(i < data.length){
            if(data[i] === HDLC.ESC){
                unescapedData = Buffer.concat([unescapedData, Buffer.from([data[i + 1] ^ HDLC.ESC_MASK])]);
                i += 2;
            } else {
                unescapedData = Buffer.concat([unescapedData, Buffer.from([data[i]])]);
                i++;
            }
        }

        return unescapedData;

    }

}

export default HDLC;
