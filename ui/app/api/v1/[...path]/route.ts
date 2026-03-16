/**
 * Catch-all API proxy route.
 *
 * Forwards every /api/v1/* request from the browser to the backend API server.
 * This runs server-side inside the Next.js container, so "http://api:8080"
 * (Docker internal DNS) is reachable — the browser never needs to know about it.
 */

const API_URL = process.env.INTERNAL_API_URL || 'http://localhost:8080'

async function handler(req: Request) {
  const url = new URL(req.url)
  // Reconstruct the full backend URL keeping path + query string
  const target = `${API_URL}${url.pathname}${url.search}`

  const headers = new Headers(req.headers)
  // Remove host header so the backend sees its own host
  headers.delete('host')

  const init: RequestInit = {
    method: req.method,
    headers,
  }

  // Forward the body for methods that have one
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    init.body = await req.arrayBuffer()
  }

  try {
    const upstream = await fetch(target, init)

    // Build the response, forwarding status + headers + body
    const responseHeaders = new Headers(upstream.headers)
    // Remove transfer-encoding to avoid issues with chunked responses
    responseHeaders.delete('transfer-encoding')

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: responseHeaders,
    })
  } catch (err: any) {
    return new Response(
      JSON.stringify({ detail: `Backend unreachable: ${err.message}` }),
      { status: 502, headers: { 'Content-Type': 'application/json' } },
    )
  }
}

export const GET = handler
export const POST = handler
export const PUT = handler
export const PATCH = handler
export const DELETE = handler
export const OPTIONS = handler
