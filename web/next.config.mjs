/** @type {import('next').NextConfig} */

// Static export: `NEXT_EXPORT=1 next build` produces a pure static directory at web/out, which can be dropped
// straight into an nginx web root to run. Development (next dev) does not set this variable, keeping the /api proxy and hot reload.
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo: the whole site runs on mocks, no backend, no /api proxy needed.
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

const nextConfig = {
  reactCompiler: true,
  // Allow dev resources (HMR) to be accessed from LAN IPs; add or remove as needed.
  // In dev, open access to /_next/* and HMR from any IPv4 origin (unaffected by changing LAN IPs).
  // Note: Next forbids a bare "*" for security, so a segmented wildcard is required; "*.*.*.*" matches any IPv4.
  allowedDevOrigins: ["*.*.*.*"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // Pure static export: no Node runtime; images are not optimized; each route produces <route>/index.html.
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo: no backend, no /api proxy needed.
          images: { unoptimized: true },
        }
      : {
          // Development: proxy /api/* to the Go backend (default :8787, overridable via AUTOPENTEST_API).
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

export default nextConfig;
