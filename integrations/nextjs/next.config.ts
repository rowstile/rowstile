import type { NextConfig } from "next";

// cacheComponents: create-next-app's default, and the "use cache" directive for the page that tries to cache a
// signed-in read with it (check 15)
const config: NextConfig = { cacheComponents: true };

export default config;
