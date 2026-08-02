import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "app.satoshivault.signer",
  appName: "Satoshi Vault Signer",
  webDir: "dist",
  android: {
    // Belt and braces alongside `debuggable false`: never let chrome://inspect
    // attach to the WebView. A debugger there could read the decrypted seed out
    // of an unlocked session and run arbitrary JS in the vault's origin.
    webContentsDebuggingEnabled: false,
  },
};

export default config;
