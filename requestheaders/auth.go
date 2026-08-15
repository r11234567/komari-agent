package requestheaders

import "net/http"

// ApplyAgentAuthentication applies Komari Bearer authentication and optional
// Cloudflare Access service-token credentials. Both Access fields are required.
func ApplyAgentAuthentication(headers http.Header, token, clientID, clientSecret string) {
	headers.Set("Authorization", "Bearer "+token)
	if clientID != "" && clientSecret != "" {
		headers.Set("CF-Access-Client-Id", clientID)
		headers.Set("CF-Access-Client-Secret", clientSecret)
	}
}
