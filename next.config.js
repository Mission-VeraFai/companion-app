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
      {
        protocol: "https",
        hostname: "tjzk.replicate.delivery",
        port: "",
        pathname: "/pbxt/**",
      },
      {
        protocol: "https",
        hostname: "replicate.delivery",
        port: "",
        pathname: "/pbxt/**",
      },
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
