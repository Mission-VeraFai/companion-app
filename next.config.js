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
      // Removed: replicate.delivery and a16z.com are NOT in the approved model registry.
      // To re-enable, obtain registry approval, pin to a specific verified version/digest,
      // and add integrity verification before restoring these entries.
    ],
  },
};

module.exports = nextConfig;
