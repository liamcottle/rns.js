import vue from '@vitejs/plugin-vue';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

export default {

    plugins: [
        vue(),
        nodePolyfills(),
    ],

}
