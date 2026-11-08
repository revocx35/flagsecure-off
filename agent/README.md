# Frida agent

`index.js` is the Frida script injected into `system_server`. It hooks the window-manager methods
that enforce `FLAG_SECURE` (targets mirror `LSPosed/DisableFlagSecure`) and prints `fso:`-prefixed
progress that the app parses.

Build (produces `../app/src/main/assets/agent.js`):

```bash
npm install
npm run build
```
