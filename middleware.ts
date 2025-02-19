import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { validateCSRFToken } from "./lib/csrf"

export async function middleware(request: NextRequest) {
  // Only apply to API routes
  if (request.nextUrl.pathname.startsWith("/api/")) {
    if (request.method !== "GET") {
      const csrfToken = request.headers.get("x-csrf-token")

      if (!csrfToken || !validateCSRFToken(csrfToken)) {
        return new NextResponse(JSON.stringify({ error: "Invalid CSRF token" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        })
      }
    }

    // Add security headers
    const response = NextResponse.next()
    response.headers.set("X-Frame-Options", "DENY")
    response.headers.set("X-Content-Type-Options", "nosniff")
    response.headers.set("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.set(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-eval' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
    )

    return response
  }

  return NextResponse.next()
}

export const config = {
  matcher: "/api/:path*",
}

