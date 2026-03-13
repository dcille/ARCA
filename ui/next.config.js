/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'standalone',
  // Proxy all /api/* requests to the backend API server.
  // This avoids CORS and lets the browser talk only to :3000.
  // Inside Docker the backend is at http://api:8080.
  // In local dev it defaults to http://localhost:8080.
  async rewrites() {
    const apiUrl = process.env.INTERNAL_API_URL || 'http://localhost:8080'
    return [
      {
        source: '/api/:path*',
        destination: `${apiUrl}/api/:path*`,
      },
    ]
  },
}

module.exports = nextConfig
