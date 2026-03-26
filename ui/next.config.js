/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  experimental: {
    proxyTimeout: 300_000, // 5 min proxy timeout for API routes
  },
  serverExternalPackages: [],
}

module.exports = nextConfig
