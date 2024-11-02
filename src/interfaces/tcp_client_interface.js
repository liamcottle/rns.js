const net = require('net');
const HDLC = require("../framing/hdlc");
const KISS = require("../framing/kiss");
const Packet = require("../packet");
const Identity = require("../identity");

class TCPClientInterface {

    constructor(name, host, port, kissFraming = false) {
        this.name = name;
        this.host = host;
        this.port = port;
        this.kissFraming = kissFraming;
    }

    connect() {

        // create new socket
        this.client = new net.Socket();

        // handle received data
        this.client.on('data', (data) => {
            this.onDataReceived(data);
        });

        // handle errors
        this.client.on('error', (error) => {
            this.onError(error);
        });

        // connect to server
        this.client.connect(this.port, this.host, () => {
            console.log(`Connected to: ${this.name} [${this.host}:${this.port}]`);
        });

    }

    disconnect() {
        this.client.end(() => {
            console.log(`Disconnected from: ${this.name} [${this.host}:${this.port}]`);
        });
    }

    sendData(data) {
        let framedData;
        if(this.kissFraming){
            framedData = Buffer.concat([
                Buffer.from([KISS.FEND, KISS.CMD_DATA]),
                KISS.escape(data),
                Buffer.from([KISS.FEND])
            ]);
        } else {
            framedData = Buffer.concat([
                Buffer.from([HDLC.FLAG]),
                HDLC.escape(data),
                Buffer.from([HDLC.FLAG])
            ]);
        }
        this.client.write(framedData);
    }

    onDataReceived(data) {
        if(this.kissFraming){
            this.handleKISSFrame(data);
        } else {
            this.handleHDLCFrame(data);
        }
    }

    handleKISSFrame(data) {
        let frameStart = false;
        let frameData = Buffer.alloc(0);
        for(let i = 0; i < data.length; i++){
            const byte = data[i];
            if(byte === KISS.FEND){
                if (frameStart && frameData.length > 0) {
                    this.processIncoming(KISS.unescape(frameData));
                    frameData = Buffer.alloc(0);
                }
                frameStart = true;
            } else if (frameStart) {
                frameData = Buffer.concat([frameData, Buffer.from([byte])]);
            }
        }
    }

    handleHDLCFrame(data) {
        let frameStart = false;
        let frameData = Buffer.alloc(0);
        for(let i = 0; i < data.length; i++){
            const byte = data[i];
            if(byte === HDLC.FLAG){
                if(frameStart && frameData.length > 0){
                    this.processIncoming(HDLC.unescape(frameData));
                    frameData = Buffer.alloc(0);
                }
                frameStart = true;
            } else if(frameStart){
                frameData = Buffer.concat([frameData, Buffer.from([byte])]);
            }
        }
    }

    processIncoming(data) {

        // fixme: skipping ifac packets for now
        if((data[0] & 0x80) === 0x80){
            console.log("IFAC packet received. SKIPPING FOR NOW");
            return;
        }

        // parse packet from bytes
        const packet = Packet.fromBytes(data);

        // handle received announces
        if(packet.packetType === Packet.ANNOUNCE){

            // todo if announce is for local destination, ignore it

            // handle received announce
            const validated = Identity.validateAnnounce(packet);
            console.log({
                validated,
            });

        }

    }

    onError(error) {
        console.error('Connection Error:', error);
    }

}

module.exports = TCPClientInterface;
