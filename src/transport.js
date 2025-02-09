import Identity from "./identity.js";

class Transport {

    // constants
    static BROADCAST = 0x00;
    static TRANSPORT = 0x01;
    // static RELAY = 0x02;
    // static TUNNEL = 0x03;
    // static TRANSPORT_TYPES = [this.BROADCAST, this.TRANSPORT, this.RELAY, this.TUNNEL];

    constructor(transportIdentity = null) {

        // ensure we have a transport identity
        // fixme: persist this identity across restarts?
        if(!transportIdentity){
            transportIdentity = Identity.create();
        }

        this.identity = transportIdentity;

    }

}

export default Transport;
