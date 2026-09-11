import { createApp } from 'vue';
import { createAuth0 } from '@auth0/auth0-vue';
import App from './App.vue';

const app = createApp(App);

app.use(
  createAuth0({
    domain: import.meta.env.VITE_AUTH0_DOMAIN,
    clientId: import.meta.env.VITE_AUTH0_CLIENT_ID,
    authorizationParams: {
      redirect_uri: window.location.origin + "/vue-test-app/",
      scope: "openid profile email",
      audience: import.meta.env.VITE_AUTH0_AUDIENCE,
    },
  })
);

app.mount('#app');
