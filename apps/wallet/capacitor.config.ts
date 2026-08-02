import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "app.satoshivault.wallet",
  appName: "Satoshi Vault Wallet",
  webDir: "dist",
  android: {
    // No remote WebView debugging in shipped builds — see the Signer config.
    webContentsDebuggingEnabled: false,
  },
};

export default config;
