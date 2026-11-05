import type { NextConfig } from "next";

// cacheComponents: create-next-app's default; what reads the request is inside <Suspense>
const config: NextConfig = { cacheComponents: true, partialPrefetching: true };

export default config;
