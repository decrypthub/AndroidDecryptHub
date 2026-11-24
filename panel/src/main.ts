import { createApp } from 'vue';
import App from './App.vue';
import './style.css';
import { connectWs, startPolling } from './store';

connectWs();
startPolling();
createApp(App).mount('#app');
