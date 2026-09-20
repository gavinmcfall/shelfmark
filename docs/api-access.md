# API access with an API key

Shelfmark's web interface is driven entirely by a JSON API under `/api/`. Set
the `API_KEY` environment variable and scripts, dashboards and assistants can
call the same API without a browser session. Browser logins keep working
exactly as before: it is cookie **or** key.

## Set the key

```yaml
environment:
  API_KEY: "a-long-random-secret"
```

Generate something long and random (for example `openssl rand -base64 32`).
A request carrying the key acts as an **admin**: the first admin user in
Shelfmark's user database. Create an admin before relying on the key in
OIDC-only installs. To rotate, change the variable and restart. Unset it and
the feature is off.

## Send the key

Either header works; `Authorization` wins if both are present.

```bash
curl -s -H "Authorization: Bearer $API_KEY" https://shelfmark.example.com/api/downloads/active
curl -s -H "X-Api-Key: $API_KEY" https://shelfmark.example.com/api/downloads/active
```

A request that carries the key is authenticated by the key alone. Session
cookies are ignored and none are set. A bearer value that is not the configured
key is ignored and the request continues with normal session authentication,
so reverse proxies that forward their own tokens are unaffected; without a valid
session such a request gets the usual `401 {"error": "Unauthorized"}`.

## Examples

Search, then look up releases, then queue one (the same calls the web UI makes):

```bash
curl -s -H "Authorization: Bearer $API_KEY" \
  "https://shelfmark.example.com/api/metadata/search?query=dune%20frank%20herbert"
# -> {"books":[{"provider":"hardcover","provider_id":"427363", ...}]}

curl -s -H "Authorization: Bearer $API_KEY" \
  "https://shelfmark.example.com/api/releases?provider=hardcover&book_id=427363&content_type=ebook"
# -> {"releases":[{"source":"direct_download","source_id":"...", ...}], ...}

curl -s -X POST -H "Authorization: Bearer $API_KEY" -H "Content-Type: application/json" \
  -d @release.json https://shelfmark.example.com/api/releases/download
# release.json = one object from "releases" (source and source_id are required)

curl -s -H "Authorization: Bearer $API_KEY" https://shelfmark.example.com/api/status
```

## Security notes

- The key is compared in constant time and is never logged.
- Keyed requests never set cookies and ignore any cookie sent with them.
- WebSocket (live activity) connections do not accept the key; poll `/api/status` instead.
