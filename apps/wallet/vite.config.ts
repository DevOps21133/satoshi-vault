import { defineConfig } from "vite";

export default defineConfig({
  base: "./",
  build: {
    target: "es2022",
    // No sourcemaps in the shipped bundle: they are only useful to someone
    // reading the app's internals on a device, and the readable source is on
    // GitHub anyway. Use `vite build --sourcemap` when debugging a build.
    sourcemap: false,
  },
  server: {
    port: 5181,
  },
});
