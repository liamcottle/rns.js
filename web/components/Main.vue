<template>
    <div>

        <!-- discovered peers -->
        <div class="p-2">
            <div class="font-bold">Discovered Peers</div>
            <div v-if="Object.keys(lxmfPeers).length === 0" class="text-sm text-gray-500">
                No peers discovered yet. Listening for announces...
            </div>
            <div class="mt-2 space-y-2">
                <div v-for="lxmfPeer of lxmfPeers" class="bg-white px-2 py-1 rounded shadow">
                    <div>
                        <b>{{ lxmfPeer.display_name }}</b> is {{ lxmfPeer.hops }} hops away
                    </div>
                    <div class="text-sm text-gray-500">
                        <{{ lxmfPeer.announce.destinationHash.toString("hex") }}>
                    </div>
                </div>
            </div>
        </div>

    </div>
</template>


<script>
import {LXMF, Reticulum, WebsocketClientInterface} from "@liamcottle/rns.js";

export default {
    name: 'Main',
    data() {
        return {
            rns: null,
            lxmfPeers: {},
        };
    },
    mounted() {

        // create rns instance
        this.rns = new Reticulum();

        // connect to websocket server
        this.rns.addInterface(new WebsocketClientInterface("Liam's Websocket Server", "wss://rns-wss.liamcottle.net"));

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
}
</script>
