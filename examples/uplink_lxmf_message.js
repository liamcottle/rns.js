/**
 * This example uplinks an existing lxmf message to the network.
 * You might have a QR code containing an lxm://<base64> uri.
 * The lxm uri contains an encrypted lxmf message already encrypted by the sender ready to be received by the intended recipient.
 * You won't be able to decrypt or read the message contents, but you can still send it to the intended destination.
 */
import {Destination, Reticulum, TCPClientInterface} from "../src/reticulum.js";

// create rns instance
const rns = new Reticulum();

// add interfaces
rns.addInterface(new TCPClientInterface("Test Net", "amsterdam.connect.reticulum.network", 4965));

console.log(`⌛️ Waiting for connection...`);
setTimeout(() => {

    // an lxm uri containing an encrypted lxmf message
    const uri = "lxm://qL7L9olH1HkYpFS4qDOQtlIUoHDpbQyjMBwL90DsIFDkVsg-f9f3sn-EdfG3LmcqpgFyZZ4iJwHP0zl0i7Ih4PvRSgywaJccJqNV62GUVLo266oie9NYULIwme580KLnGAm8jWxBFizkufYhsnZkIu0H_c08k4vsqrO4dyaJDnmUarz3tV0tcXXGRi6Ru7mbUni3SPJkORH596tOxiB1yWsqF7f0AowjTQ2nXaUN-70GtgZXbB6i213208AawrJAphef3u1_b7Io2Xx928m22A";

    // convert base64 in uri to bytes buffer
    const base64 = uri.replace("lxm://", "");
    const data = Buffer.from(base64, "base64url");

    // extract destination hash and encrypted data
    const destinationHash = data.slice(0, 16);
    const encryptedPayload = data.slice(16);

    rns.registerAnnounceHandler("lxmf.delivery", (event) => {
       if(event.announce.destinationHash.equals(destinationHash)){

           // create recipient destination
           const recipientDestination = rns.registerDestination(event.announce.identity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

           // override the encrypt method so it doesn't double encrypt the already encrypted data
           recipientDestination.encrypt = (data) => {
               return data;
           };

           // send existing encrypted message
           console.log(`📤 Sending LXMF message...`);
           recipientDestination.send(encryptedPayload, event.announce.transportId);

           // we are done here
           setTimeout(() => {
               console.log(`✅ Done`);
               process.exit();
           }, 1000);

       }
    });

    // request path to destination from network
    console.log(`🔄 Requesting path to <${destinationHash.toString("hex")}>`);
    rns.transport.requestPath(destinationHash);

}, 3000);
