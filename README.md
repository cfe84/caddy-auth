# Caddy Auth

Caddy Auth is a Caddy HTTP middleware and a small central sign-in service. It protects whole sites or selected paths with credential-role membership checks. The service uses SQLite, Argon2id password hashes, short-lived one-use PKCE authorization codes, opaque server-side grants, and a 12-hour absolute SSO session.

Building requires Go 1.25 or newer. SQLite uses a pure-Go driver, so CGO and a C compiler are not required.

## Build

```sh
make build
make test
sudo make install
```

`make install` installs all three binaries into `$(PREFIX)/bin` (default `/usr/local/bin`). Use `make install PREFIX="$HOME/.local"` for a user-local install; `DESTDIR` and `BINDIR` can also be overridden.

`cmd/caddy-auth` is a Caddy build with this plugin registered. Use this binary for `adapt`, `validate`, and serving the configuration; a stock Caddy binary does not include the module.

The module root also registers the plugin for `xcaddy` builds:

```sh
xcaddy build --with github.com/cfe84/caddy-auth@<tag-or-commit>
```

## Bootstrap

1. Generate one random instance secret and set it for both `authd` and Caddy. This creates a 64-character hex secret:

   ```sh
   export AUTH_INSTANCE_TOKEN="$(openssl rand -hex 32)"
   export CADDY_AUTH_INSTANCE_TOKEN="$AUTH_INSTANCE_TOKEN"
   ```

   Keep it private; it authorizes site registration, code exchange, and grant validation.
2. Run `authd` with the same `CADDY_AUTH_DB` and `CADDY_AUTH_INSTANCE_TOKEN` behind HTTPS at the configured service URL. By default it listens on `127.0.0.1:8090` and stores data in `caddy-auth.db`. The reverse proxy must preserve POST bodies; the service still requires the bearer credential on every privileged API even if those paths are browser-reachable through the proxy.
3. Create a credential, role, membership, and explicit callback origin:

   ```sh
   mkdir -p /var/lib/caddy-auth
   export CADDY_AUTH_DB=/var/lib/caddy-auth/auth.db
   ./authctl role add accounting
   ./authctl credential add alice       # password prompt is hidden in a terminal; stdin can be piped
   ./authctl membership add alice accounting
   ./authctl site add https://app.example.com
   ```

   Repeat `site add` for each exact HTTPS host/port. Wildcards, paths, query strings, userinfo, and non-HTTPS origins are rejected. Site registration is an explicit bootstrap action; the service never trusts a browser-supplied `Host` to add a callback. The authenticated `/api/sites` endpoint is available for a trusted deployment controller, but this build does not infer site addresses from Caddy's opaque JSON server routes or synchronize them automatically.

4. Configure Caddy (see [`examples/Caddyfile`](examples/Caddyfile)):

   ```caddyfile
   {
       auth {
           service https://auth.example.com
           instance_token {$AUTH_INSTANCE_TOKEN}
       }
   }

   app.example.com {
       require_auth {
           role accounting
           ttl 1h
       }
       reverse_proxy accounting:8080
   }

   reports.example.com {
       @private path /reports/*
       require_auth @private {
           role accounting
           ttl 15m
       }
       reverse_proxy reports:8080
   }
   ```

   The middleware inserts a handler for `/_caddy_auth/callback` alongside every protected route, before the proxy directive. No portal route is needed. This reserved path avoids common application collisions; it is not a security boundary. Protect it from being served by application handlers.

`ttl` limits the age of a Caddy authorization grant, not the SSO session. A request with a grant older than the endpoint TTL silently gets a fresh opaque grant if SSO is still valid. Grants never extend past the 12-hour SSO expiry. Each request validates current account enablement and role membership; disabling a credential or removing its membership takes effect on the next request. Password changes and SSO sign-out invalidate sessions and their grants.

The authorization cookie is secure, HttpOnly, SameSite=Lax, host-only, and uses the `__Host-` prefix. Its name is derived from the exact HTTPS origin so two sites on different ports of one hostname do not overwrite each other's cookie. It is never sent upstream; flow cookies are also removed while unrelated application cookies and Authorization headers are preserved. A successful callback redirects to the original local path and query with the callback query removed. POST request bodies are not replayed after sign-in: clients should retry the original POST after the redirect.

Sign out at `https://auth.example.com/logout` using the displayed CSRF-protected form. This revokes the central SSO session and all grants tied to it.

## Administration

```sh
./authctl credential disable alice
./authctl credential enable alice
./authctl credential set-password alice
./authctl membership remove alice accounting
./authctl role remove accounting
```

The database is the authority for credentials, roles, site origins, sessions, authorization codes, and grants. Back it up with SQLite-aware tooling. Keep it on persistent storage; deleting it revokes every session and grant.

## Limits

Login-attempt state is held in the Caddy process with a five-minute expiry and a hard 10,000-attempt limit. Therefore a Caddy restart invalidates in-progress sign-ins and multiple Caddy replicas do not share login attempts; use a shared state implementation before running multiple replicas. The auth service also uses SQLite and should be run as one service instance against one local database. There is no user-management UI, role hierarchy, federation, or HA database support.

Credential POSTs are limited to 10 attempts per source IP per minute. Behind the default loopback proxy, the service uses the first valid `X-Forwarded-For` address from that loopback peer; do not configure other untrusted clients as trusted proxies.

The default auth service listener is loopback-only and uses plain HTTP, so deploy it behind the HTTPS Caddy site shown in the example, or provide an equivalent private TLS endpoint. Do not publish the trusted API paths to browsers. Caddy's connection to the service uses bounded five-second timeouts and protected routes fail closed with 503 when the service is unavailable.

## Verify

```sh
go test ./...
AUTH_SERVICE=https://auth.example.com AUTH_INSTANCE_TOKEN=replace-with-at-least-32-characters \
  ./caddy-auth adapt --config examples/Caddyfile --adapter caddyfile
AUTH_SERVICE=https://auth.example.com AUTH_INSTANCE_TOKEN=replace-with-at-least-32-characters \
  ./caddy-auth validate --config examples/Caddyfile --adapter caddyfile
```
