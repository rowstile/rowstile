import type { NextConfig } from "next";

// The edge runtime's routes, an app of their own: Next refuses a route's `runtime` in an app with "use cache"
// (experimental.useCache, cacheComponents), which the app beside this folder has for check 15
const config: NextConfig = {};

export default config;
