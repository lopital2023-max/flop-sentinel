import { defineConfig } from "astro/config";

const configuredBase = process.env.BASE_PATH || "/";

export default defineConfig({
  site: process.env.PUBLIC_SITE_URL || "https://lopital2023-max.github.io",
  base: configuredBase,
  output: "static",
  build: {
    assets: "assets",
    inlineStylesheets: "never",
  },
  vite: {
    build: {
      sourcemap: true,
      assetsInlineLimit: 0,
    },
  },
});
