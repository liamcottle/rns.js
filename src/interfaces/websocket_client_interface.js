import Packet from "../packet.js";
import Interface from "./interface.js";

class WebsocketClientInterface extends Interface {

    constructor(name, host, port = 443, type = "wss") {
        super(name);
        this.host = host;
        this.port = port;
        this.type = type;
    }

    connect() {

        // connect to websocket
        this.websocket = new WebSocket(`${this.type}://${this.host}:${this.port}`);

        // connect to server
        this.websocket.addEventListener("open", () => {
            console.log(`Connected to: ${this.name} [${this.type}://${this.host}:${this.port}]`);
        });

        // handle received data
        this.websocket.addEventListener('message', async (message) => {
            const arrayBuffer = await message.data.arrayBuffer();
            this.onDataReceived(Buffer.from(arrayBuffer));
        });

        // handle errors
        this.websocket.addEventListener('error', (error) => {
            this.onSocketError(error);
        });

        // handle socket close
        this.websocket.addEventListener('close', (error) => {
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
