import { createApp } from 'vue';
import App from './App.vue';
import './style.css';
import './studio.css';
import { connectWs, startPolling } from './store';
import {
  create, NButton, NCheckbox, NConfigProvider, NDatePicker, NDropdown, NEmpty, NIcon, NInput,
  NInputNumber, NModal, NPopconfirm, NRadioButton, NRadioGroup, NSelect, NSpin, NSwitch, NTag, NTooltip,
} from 'naive-ui';

const naive = create({
  components: [NButton, NCheckbox, NConfigProvider, NDatePicker, NDropdown, NEmpty, NIcon, NInput,
    NInputNumber, NModal, NPopconfirm, NRadioButton, NRadioGroup, NSelect, NSpin, NSwitch, NTag, NTooltip],
});

const app = createApp(App);
app.use(naive);

connectWs();
startPolling();
app.mount('#app');
