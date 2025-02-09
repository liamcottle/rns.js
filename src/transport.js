import Identity from "./identity.js";
import Destination from "./destination.js";
import Cryptography from "./cryptography.js";

class Transport {

    // constants
    static BROADCAST = 0x00;
    static TRANSPORT = 0x01;
    // static RELAY = 0x02;
    // static TUNNEL = 0x03;
    // static TRANSPORT_TYPES = [this.BROADCAST, this.TRANSPORT, this.RELAY, this.TUNNEL];

    constructor(rns, transportIdentity = null) {

        this.rns = rns;

        // ensure we have a transport identity
        // fixme: persist this identity across restarts?
        if(!transportIdentity){
            transportIdentity = Identity.create();
        }

        this.identity = transportIdentity;
        this.pathRequestDestination = this.rns.registerDestination(null, Destination.OUT, Destination.PLAIN, "rnstransport", "path", "request");

    }

    requestPath(destinationHash) {

        // if string provided, convert to bytes
        if(typeof destinationHash === "string"){
            destinationHash = Buffer.from(destinationHash, "hex");
        }

        // create a random tag
        const requestTag = Cryptography.getRandomHash();

        // prepare path request data
        const pathRequestData = Buffer.concat([
            destinationHash,
            this.identity.hash, // transport identity hash
            requestTag,
        ]);

        // send path request
        this.pathRequestDestination.send(pathRequestData);

    }

}

export default Transport;
