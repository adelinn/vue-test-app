<script setup lang="ts">
import { useAuth0 } from '@auth0/auth0-vue'

const {
  loginWithRedirect,
  logout,
  user,
  isAuthenticated,
  isLoading,
  error,
} = useAuth0()

const login = () => loginWithRedirect()

const requestMfaAccess = () =>
  loginWithRedirect({
    authorizationParams: {
      redirect_uri: window.location.origin + "/vue-test-app/",
      audience: import.meta.env.VITE_AUTH0_AUDIENCE,
      scope: 'openid profile email mfa',
    },
  })

const signOut = () =>
  logout({
    logoutParams: {
      returnTo: window.location.origin + "/vue-test-app/",
    },
  })
</script>

<template>
  <main>
    <p v-if="isLoading">Loading...</p>
    <p v-else-if="error">Authentication failed: {{ error.message }}</p>

    <template v-else-if="isAuthenticated">
      <h1>Welcome, {{ user?.nickname ?? user?.name ?? user?.email }}</h1>
      <button type="button" @click="requestMfaAccess">
        Access high privileged functionality (requres MFA)
      </button>
      <button type="button" @click="signOut">Log out</button>
    </template>

    <template v-else>
      <h1>Welcome</h1>
      <button type="button" @click="login">Log in</button>
    </template>
  </main>
</template>