import {createApp, defineAsyncComponent} from 'vue';
import { createRouter, createWebHashHistory } from 'vue-router';
import "./style.css";
import App from "./components/App.vue";

const router = createRouter({
    history: createWebHashHistory(),
    routes: [
        {
            name: "main",
            path: '/',
            component: defineAsyncComponent(() => import("./components/MainPage.vue")),
        },
    ],
})

createApp(App)
    .use(router)
    .mount('#app');
