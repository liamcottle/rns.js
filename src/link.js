const { ed25519, x25519 } = require("@noble/curves/ed25519");
const { pack: msgpack } = require('msgpackr');
const Packet = require("./packet");
const Transport = require("./transport");
const Identity = require("./identity");
const Cryptography = require("./cryptography");
const Destination = require("./destination");
const Fernet = require("./fernet");
const EventEmitter = require("./utils/events");

class Link extends EventEmitter {

    static KEYSIZE = 32;
    static ECPUBSIZE = 32 + 32;

    static PENDING = 0x00;
    static HANDSHAKE = 0x01;
    static ACTIVE = 0x02;
    // static STALE = 0x03;
    // static CLOSED = 0x04;

    constructor() {
        super();
    }

    establish(destination) {

        this.initiator = true;
        this.status = Link.PENDING;
        this.destination = destination;

        this.privateKeyBytes = Buffer.from(x25519.utils.randomPrivateKey());
        this.signaturePrivateKeyBytes = Buffer.from(ed25519.utils.randomPrivateKey());

        this.publicKeyBytes = Buffer.from(x25519.getPublicKey(this.privateKeyBytes));
        this.signaturePublicKeyBytes = Buffer.from(x25519.getPublicKey(this.signaturePrivateKeyBytes));

        this.loadPeerKeysFromIdentity(destination.identity);

        if(this.initiator){

            // create link request data
            const requestData = Buffer.concat([
                this.publicKeyBytes,
                this.signaturePublicKeyBytes,
            ]);

            // create link request packet
            const packet = new Packet();
            packet.headerType = Packet.HEADER_1;
            packet.packetType = Packet.LINKREQUEST;
            packet.transportType = Transport.BROADCAST;
            packet.context = Packet.NONE;
            packet.contextFlag = Packet.FLAG_UNSET;
            packet.destination = destination;
            packet.destinationHash = destination.hash;
            packet.destinationType = destination.type;
            packet.data = requestData;
            const packed = packet.pack();

            // set link id
            this.setLinkId(packet);

            // register link in transport
            this.requestTime = Date.now();
            this.destination.rns.registerLink(this);

            // todo start watchdog

            // fixme: only send on relevant interface
            // send link request
            console.log(`Sending Link request ${this.hash.toString("hex")} to ${destination.hash.toString("hex")}`)
            destination.rns.sendData(packed);

        }

    }

    loadPeerKeys(peerPublicKeyBytes, peerSignaturePublicKeyBytes) {
        this.peerPublicKeyBytes = peerPublicKeyBytes;
        this.peerSignaturePublicKeyBytes = peerSignaturePublicKeyBytes;
    }

    loadPeerKeysFromIdentity(identity) {
        this.loadPeerKeys(identity.publicKeyBytes, identity.signaturePublicKeyBytes);
    }

    setLinkId(packet) {
        // this.linkId = packet.getTruncatedHash();
        this.hash = packet.getTruncatedHash();
    }

    validateProof(proofPacket) {
        try {

            console.log("validating link proof");

            // do nothing if not in pending state
            if(this.status !== Link.PENDING){
                console.log("ignoring link proof validation as link is not in pending state");
                return;
            }

            // do nothing if not initiator
            if(!this.initiator){
                console.log("ignoring link proof validation as we didn't initiate this link");
                return;
            }

            // ensure link proof data size is as expected
            console.log(proofPacket);
            if(proofPacket.data.length !== Identity.SIGLENGTH_IN_BYTES + Link.ECPUBSIZE / 2){
                console.log("link proof validation failed: invalid packet data length");
                return;
            }

            // load peer keys
            const peerPublicKeyBytes = proofPacket.data.slice(Identity.SIGLENGTH_IN_BYTES, Identity.SIGLENGTH_IN_BYTES + Link.ECPUBSIZE / 2);
            const peerSignaturePublicKeyBytes = this.destination.identity.signaturePublicKeyBytes;
            this.loadPeerKeys(peerPublicKeyBytes, peerSignaturePublicKeyBytes);

            // perform handshake
            this.handshake();

            const signedData = Buffer.concat([
                this.hash,
                this.peerPublicKeyBytes,
                this.peerSignaturePublicKeyBytes,
            ]);

            const signature = proofPacket.data.slice(0, Identity.SIGLENGTH_IN_BYTES);

            // validate link proof signature
            if(!this.destination.identity.validate(signature, signedData)){
                console.log(`Invalid link proof signature received by ${this.hash.toString("hex")}. Ignoring.`);
                return;
            }

            // ensure link is in handshake state
            if(this.status !== Link.HANDSHAKE){
                console.log(`Invalid link state for proof validation: ${this.status}`);
                return;
            }

            // update state
            this.rtt = Date.now() - this.requestTime;
            // self.attached_interface = packet.receiving_interface
            // self.__remote_identity = self.destination.identity
            this.status = Link.ACTIVE;
            this.activatedAt = Date.now();
            this.lastProof = this.activatedAt;
            this.destination.rns.activateLink(this);

            console.log(`Link ${this.hash.toString("hex")} established with ${this.destination.hash.toString("hex")}, RTT is ${this.rtt}ms`);

            // send rtt packet
            const rttData = msgpack(this.rtt / 1000);

            // create data packet
            const rttPacket = new Packet();
            rttPacket.hops = 0;
            rttPacket.headerType = Packet.HEADER_1;
            rttPacket.packetType = Packet.DATA;
            rttPacket.transportType = Transport.BROADCAST;
            rttPacket.context = Packet.LRRTT;
            rttPacket.contextFlag = Packet.FLAG_UNSET;
            rttPacket.destination = this;
            rttPacket.destinationHash = this.hash;//.slice(Constants.TRUNCATED_HASHLENGTH_IN_BYTES);
            rttPacket.destinationType = Destination.LINK;
            rttPacket.data = rttData;

            // pack packet
            const raw = rttPacket.pack();

            // fixme: only send to receiving interface, and to reverse path table
            // send packet to all interfaces
            this.destination.rns.sendData(raw);

            // todo fire callback link_established
            this.emit("established");

            // if self.rtt != None and self.establishment_cost != None and self.rtt > 0 and self.establishment_cost > 0:
            // self.establishment_rate = self.establishment_cost/self.rtt
            //
            // rtt_data = umsgpack.packb(self.rtt)
            // rtt_packet = RNS.Packet(self, rtt_data, context=RNS.Packet.LRRTT)
            // rtt_packet.send()
            // self.had_outbound()
            //
            // if self.callbacks.link_established != None:
            // thread = threading.Thread(target=self.callbacks.link_established, args=(self,))
            // thread.daemon = True
            // thread.start()

        } catch(e) {
            console.log("failed to validate link proof", e);
        }
    }

    handshake() {

        // prevent handshaking if link is not in pending state
        if(this.status !== Link.PENDING){
            console.log(`Handshake attempt on ${this.hash.toString("hex")} with invalid state ${this.status}`);
            return;
        }

        // update state
        this.status = Link.HANDSHAKE;

        // compute shared key
        this.sharedKey = Buffer.from(x25519.getSharedSecret(this.privateKeyBytes, this.peerPublicKeyBytes));

        // create derived key
        this.derivedKey = Cryptography.hkdf(32, this.sharedKey, this.hash);

    }

    encrypt(data) {
        const fernet = new Fernet(this.derivedKey);
        return fernet.encrypt(data);
    }

    decrypt(data) {
        const fernet = new Fernet(this.derivedKey);
        return fernet.decrypt(data);
    }

    send(data) {

        // create data packet
        const packet = new Packet();
        packet.headerType = Packet.HEADER_1;
        packet.packetType = Packet.DATA;
        packet.transportType = Transport.BROADCAST;
        packet.context = Packet.NONE;
        packet.contextFlag = Packet.FLAG_UNSET;
        packet.destination = this;
        packet.destinationHash = this.hash;
        packet.destinationType = Destination.LINK;
        packet.data = data;

        // pack packet
        const raw = packet.pack();

        // send packet to all interfaces
        this.destination.rns.sendData(raw);

    }

    onPacket(packet) {

        // decrypt packet data
        const plaintext = this.decrypt(packet.data);

        // set link on packet so prove will have access to it
        packet.destination = this;
        packet.link = this;

        // fire event
        this.emit("packet", {
            packet: packet,
            data: plaintext,
        });

    }

}

module.exports = Link;
