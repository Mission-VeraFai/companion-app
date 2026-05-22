/** @type {import('next').NextConfig} */
const nextConfig = {
  experimental: {
    serverActions: true,
  },
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "avatars.githubusercontent.com",
        port: "",
        pathname: "**",
      },
      // replicate.delivery and tjzk.replicate.delivery have been removed:
      // these hosts are NOT in the approved model registry and the wildcard
      // pathname /pbxt/** provides no version or integrity constraint.
      // To serve Replicate-generated images, proxy them through an approved
      // internal endpoint with explicit version pinning before re-adding here.
      {
        protocol: "https",
        hostname: "a16z.com",
        port: "",
        pathname: "/images/**",
      },
    ],
  },
};

module.exports = nextConfig;
