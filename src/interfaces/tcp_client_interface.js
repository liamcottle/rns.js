import { Socket } from "net";
import HDLC from "../framing/hdlc.js";
import KISS from "../framing/kiss.js";
import Packet from "../packet.js";
import Interface from "./interface.js";

class TCPClientInterface extends Interface {

    constructor(name, host, port, kissFraming = false) {
        super(name);
        this.host = host;
        this.port = port;
        this.kissFraming = kissFraming;
    }

    connect() {

        // create new socket
        this.socket = new Socket();

        // handle received data
        this.socket.on('data', (data) => {
            this.onSocketDataReceived(data);
        });

        // handle errors
        this.socket.on('error', (error) => {
            this.onSocketError(error);
        });

        // handle socket close
        this.socket.on('close', (error) => {
            this.onSocketClose(error);
        });

        // connect to server
        this.socket.connect(this.port, this.host, () => {
            console.log(`Connected to: ${this.name} [${this.host}:${this.port}]`);
        });

    }

    onSocketDataReceived(data) {
        if(this.kissFraming){
            this.handleKISSFrame(data);
        } else {
            this.handleHDLCFrame(data);
        }
    }

    onSocketError(error) {
        console.error('Connection Error', error);
    }

    onSocketClose() {

        console.error('Connection Closed');

        // auto reconnect
        setTimeout(() => {
            this.connect();
        }, 1000);

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
        this.socket.write(framedData);
    }

    handleKISSFrame(data) {
        let frameStart = false;
        let frameData = Buffer.alloc(0);
        for(let i = 0; i < data.length; i++){
            const byte = data[i];
            if(byte === KISS.FEND){
                if(frameStart && frameData.length > 0){
                    this.processIncoming(KISS.unescape(frameData));
                    frameData = Buffer.alloc(0);
                }
                frameStart = true;
            } else if(frameStart){
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

        // pass to rns
        this.rns.onPacketReceived(packet, this);

    }

}

export default TCPClientInterface;
