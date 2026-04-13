import { defineConfig } from "astro/config";
import react from "@astrojs/react";

export default defineConfig({
  integrations: [react()],
  site: "https://jamesmeow.github.io",
  base: "/xdr-pivot-map",
  output: "static",
});
