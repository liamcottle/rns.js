<template>
    <div>

        <!-- discovered peers -->
        <div class="p-2">
            <div class="font-bold">Discovered Peers</div>
            <div v-if="Object.keys(lxmfPeers).length === 0" class="text-sm text-gray-500">
                No peers discovered yet. Listening for announces...
            </div>
            <div>
                <div class="flex space-x-1">
                    <div class="my-auto">
                        <input type="text" placeholder="Enter destination hash" v-model="destinationHash" class="bg-gray-50 border border-gray-300 text-gray-900 text-sm rounded-lg focus:ring-blue-500 focus:border-blue-500 block w-full p-2.5">
                    </div>
                    <div class="my-auto">
                        <button @click="requestPath(destinationHash)" type="button" class="bg-green-500 hover:bg-green-400 focus-visible:outline-green-500 my-auto inline-flex items-center gap-x-1 rounded-md p-2 text-sm font-semibold text-white shadow-sm focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2">
                            Request Path
                        </button>
                    </div>
                </div>
            </div>
            <div class="mt-2 space-y-2">
                <div v-for="lxmfPeer of lxmfPeers" class="bg-white px-2 py-1 rounded shadow">
                    <div>
                        <b>{{ lxmfPeer.display_name }}</b> is {{ lxmfPeer.hops }} hops away <span v-if="lxmfPeer.announce.isPathResponse" class="text-purple-500">(From Path Request)</span>
                    </div>
                    <div class="text-sm text-gray-500">
                        <{{ lxmfPeer.announce.destinationHash.toString("hex") }}>
                    </div>
                    <div class="flex space-x-1 text-sm text-gray-500">
                        <a @click="sendMessage(lxmfPeer)" href="javascript:void(0);" class="text-blue-500 underline">Send Message</a>
                        <span>•</span>
                        <a @click="generateEncryptedQrMessage(lxmfPeer.announce.identity)" href="javascript:void(0);" class="text-blue-500 underline">Generate QR Message</a>
                        <span>•</span>
                        <a @click="requestPath(lxmfPeer.announce.destinationHash)" href="javascript:void(0);" class="text-blue-500 underline">Request Path</a>
                    </div>
                </div>
            </div>
        </div>

    </div>
</template>


<script>
import {
    Destination,
    Identity,
    LXMessage,
    LXMF,
    LXMRouter,
    Reticulum,
    WebsocketClientInterface
} from "@liamcottle/rns.js";

export default {
    name: 'Main',
    data() {
        return {

            rns: null,
            identity: null,
            lxmfRouter: null,
            lxmfPeers: {},

            destinationHash: null,

        };
    },
    mounted() {

        // create rns instance
        this.rns = new Reticulum();

        // connect to websocket server
        this.rns.addInterface(new WebsocketClientInterface("Liam's Websocket Server", "wss://rns-wss.liamcottle.net"));

        // create test identity
        // this.identity = Identity.create();
        this.identity = Identity.fromPrivateKey(Buffer.from("9339cfce1fc75d4db4697cada620bb229de8a2164287c9302dbce840f38af39452f63722ef745fcef7bb3f90984b80c43a77ad1ff11127b88035b4ae4e670eaa", "hex"));

        // create lxmf router
        this.lxmfRouter = new LXMRouter(this.rns, this.identity);
        this.lxmfRouter.on("message", (lxmfMessage) => {
            alert(lxmfMessage.content);
        });

        // wait a bit for websocket connection to be connected
        // fixme: have a callback from rns when interfaces are ready?
        setTimeout(() => {
            this.lxmfRouter.announce("@liamcottle/rns.js");
        }, 3000);

        // listen for all announces
        this.rns.on("announce", (data) => {
            console.log(`${data.announce.destinationHash.toString("hex")} is now ${data.hops} hops away on interface [${data.interface_name}] public key: ${data.announce.identity.getPublicKey().toString("hex")}`);
        });

        // listen for lxmf.delivery announces
        this.rns.registerAnnounceHandler("lxmf.delivery", (data) => {
            console.log("on lxmf.delivery announce", data);
            this.lxmfPeers[data.announce.destinationHash] = {
                hops: data.hops,
                announce: data.announce,
                identity: data.identity,
                display_name: LXMF.displayNameFromAppData(data.announce.appData),
            }
        });

    },
    methods: {
        requestPath(destinationHash) {
            this.rns.transport.requestPath(destinationHash);
        },
        sendMessage(lxmfPeer) {

            // ask user for message
            const message = prompt("Enter message");
            if(!message){
                return;
            }

            // create recipient destination
            const recipientDestination = this.rns.registerDestination(lxmfPeer.announce.identity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

            // create lxmf message
            const replyLxmfMessage = new LXMessage();
            replyLxmfMessage.sourceHash = this.lxmfRouter.destination.hash;
            replyLxmfMessage.destinationHash = recipientDestination.hash;
            replyLxmfMessage.title = "";
            replyLxmfMessage.content = message;
            replyLxmfMessage.fields = new Map();

            // send it
            const packed = replyLxmfMessage.pack(this.identity);
            recipientDestination.send(packed, lxmfPeer.announce.transportId);

        },
        generateEncryptedQrMessage(recipientIdentity) {

            // ask user for message
            const message = prompt("Enter message");
            if(!message){
                return;
            }

            // create recipient destination
            const recipientDestination = this.rns.registerDestination(recipientIdentity, Destination.OUT, Destination.SINGLE, "lxmf", "delivery");

            // create lxmf message
            const replyLxmfMessage = new LXMessage();
            replyLxmfMessage.sourceHash = this.lxmfRouter.destination.hash;
            replyLxmfMessage.destinationHash = recipientDestination.hash;
            replyLxmfMessage.title = "";
            replyLxmfMessage.content = message;
            replyLxmfMessage.fields = new Map();

            // convert to lxm:// uri
            const lxmUri = replyLxmfMessage.toLxmUri(this.identity, recipientIdentity);

            // open qr code in new tab
            const qrCodeUrl = "https://api.qrserver.com/v1/create-qr-code/?size=500x500&data=" + encodeURIComponent(lxmUri);
            window.open(qrCodeUrl, "_blank");

        },
    },
}
</script>
