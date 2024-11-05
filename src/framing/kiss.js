class KISS {

    static FEND = 0xC0;
    static FESC = 0xDB;
    static TFEND = 0xDC;
    static TFESC = 0xDD;
    static CMD_DATA = 0x00;

    static escape(data) {

        let escapedData = Buffer.alloc(0);
        for(const byte of data){
            if(byte === KISS.FEND){
                escapedData = Buffer.concat([escapedData, Buffer.from([KISS.FESC, KISS.TFEND])]);
            } else if(byte === KISS.FESC){
                escapedData = Buffer.concat([escapedData, Buffer.from([KISS.FESC, KISS.TFESC])]);
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
            if(data[i] === KISS.FESC){
                if(data[i + 1] === KISS.TFEND){
                    unescapedData = Buffer.concat([unescapedData, Buffer.from([KISS.FEND])]);
                } else if(data[i + 1] === KISS.TFESC) {
                    unescapedData = Buffer.concat([unescapedData, Buffer.from([KISS.FESC])]);
                }
                i += 2;
            } else {
                unescapedData = Buffer.concat([unescapedData, Buffer.from([data[i]])]);
                i++;
            }
        }

        return unescapedData;

    }

}

export default KISS;
