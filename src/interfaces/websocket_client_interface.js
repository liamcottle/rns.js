import { WebSocket } from "ws";
import Packet from "../packet.js";
import Interface from "./interface.js";

class WebsocketClientInterface extends Interface {

    constructor(name, host, port) {
        super(name);
        this.host = host;
        this.port = port;
    }

    connect() {

        // connect to websocket
        // fixme: implement support for wss:// so it can work in web browsers
        this.websocket = new WebSocket(`ws://${this.host}:${this.port}`);

        // connect to server
        this.websocket.on("open", () => {
            console.log(`Connected to: ${this.name} [${this.host}:${this.port}]`);
        });

        // handle received data
        this.websocket.on('message', (data) => {
            this.onDataReceived(data);
        });

        // handle errors
        this.websocket.on('error', (error) => {
            this.onSocketError(error);
        });

        // handle socket close
        this.websocket.on('close', (error) => {
            this.onSocketClose(error);
        });

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
        this.websocket.send(data);
    }

    onDataReceived(data) {
        this.processIncoming(data);
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

export default WebsocketClientInterface;
