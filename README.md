# easysuite/common

Gemeinsames Laravel-Paket aller EasySuite-Systeme (Orbis, Security, Billing, weitere Apps).
Es setzt die Verträge aus `Auth-EasySuite/docs/architecture/` um: OIDC-Login, Token-Prüfung, S2S-Aufrufe, Events.

**Wichtig:** Das Paket **prüft** Tokens, es stellt keine aus. Auth-EasySuite braucht es nur für die Event-Teile.

## Einbindung

```json
"repositories": [{ "type": "path", "url": "../Common-EasySuite" }],
"require": { "easysuite/common": "@dev" }
```

```bash
php artisan vendor:publish --tag=easysuite-config
php artisan migrate            # Event-Outbox (nur nötig, wenn das System Events sendet)
```

`.env`:

```
EASYSUITE_ISSUER=https://auth.easysuite.ch
EASYSUITE_CLIENT_ID=            # dieses System als Client in Auth, zugleich erwartete `aud`
EASYSUITE_CLIENT_SECRET=
EASYSUITE_SELF_URL=https://orbis.easysuite.ch
EASYSUITE_REDIRECT_URI=         # optional, Standard: <SELF_URL>/auth/callback
EASYSUITE_ORBIS_AUDIENCE=       # client_id der Ziel-Systeme (für S2S)
EASYSUITE_CACHE_STORE=redis     # gemeinsamer Store, wenn mehrere Instanzen laufen
```

## 1. Browser-Login

Routen (automatisch): `GET /auth/redirect`, `GET /auth/callback`, `POST /auth/logout`,
`POST /auth/backchannel-logout`, dazu `GET /login` (Name `login`) für Laravels `Authenticate`.

```php
Route::middleware(['web', 'auth', 'easysuite.session'])->group(function () { … });
```

- Flow: Authorization Code + PKCE (S256), `state`, `nonce`. Das Token wird gegen das JWKS geprüft.
- Der lokale User ist nur ein Stub (`uuid` = `sub`, `tenant_id` = `tid`, `name`, `email`). Eigene Logik: `easysuite.login.provisioner` (Interface `UserProvisioner`).
- Step-up: `/auth/redirect?acr_values=mfa&max_age=900`.
- `easysuite.session` beendet die Session, sobald ihre `sid` per Back-Channel-Logout / Event gesperrt wurde.
- SaaS-Panel: `->middleware(['web', 'auth', 'easysuite.saas-admin'])` (Claim `saas_admin` **und** MFA).
- Die Tokens der Session liegen unter `session('easysuite.tokens')` (für Token Exchange).

## 2. APIs schützen

```php
Route::middleware(['easysuite.token', 'easysuite.scope:orbis:users.read'])->get('/s2s/users/{uuid}/roles', …);
Route::middleware(['easysuite.token', 'easysuite.type:user'])->get('/api/me', fn (Request $r) => $r->attributes->get('easysuite.token')->sub());
```

| Middleware | Prüft |
|---|---|
| `easysuite.token` | Signatur (RS256, JWKS), `iss`, `aud` = eigene client_id, `exp`/`nbf`/`iat`, Sperrliste. Setzt `TenantContext` |
| `easysuite.scope:a,b` | alle Scopes vorhanden |
| `easysuite.type:user\|app` | Mensch (delegiert) oder App (`client_credentials`) |
| `easysuite.saas-admin` | `saas_admin` + MFA |

Zugriff aufs Token: `$request->attributes->get('easysuite.token')` (`VerifiedToken`: `sub()`, `tid()`, `sid()`, `scopes()`, `hasScope()`, `isApp()`, `hasMfa()` …).
Tenant-Scoping für Models: Trait `EasySuite\Common\Support\BelongsToTenant`.

## 3. Andere Systeme aufrufen

```php
$response = app(\EasySuite\Common\S2S\Client::class)
    ->request('orbis', ['orbis:users.read'])         // client_credentials, Token gecacht
    ->get("/s2s/users/{$uuid}/roles");
```

## 4. Events

**Senden** (in derselben DB-Transaktion wie die Änderung):

```php
DB::transaction(function () use ($tenant) {
    $tenant->save();
    app(EventPublisher::class)->publish('tenant.created', Subject::tenant($tenant->id), $tenant->id);
});
```

Empfänger in `easysuite.events.subscriptions`. Schlägt die Zustellung fehl, wiederholt `easysuite:events:dispatch` (Scheduler: jede Minute) mit Backoff, danach `dead`.

**Empfangen:** `POST /s2s/events` ist fertig verdrahtet. Handler registrieren:

```php
app(EventRegistry::class)->on('tenant.created', fn (ReceivedEvent $e) => SyncTenant::dispatch($e->subjectId()));
```

Eingebaut: `session.revoked` und `user.disabled` füllen die Sperrliste. Vertrauenswürdige Aussteller: `easysuite.events.trusted_issuers`.

## Tests in den Systemen

```php
$auth = \EasySuite\Common\Testing\FakeAuthServer::install();  // Config + Http::fake
$this->withToken($auth->accessToken(['scopes' => ['orbis:users.read'], 'tid' => 't1']))->getJson('/…');
$this->withToken($auth->appToken(['scopes' => ['x']]))->getJson('/…');
```

## Entwicklung

```bash
composer install && composer test && composer lint
```

Windows: PHP braucht `extras/ssl/openssl.cnf` für Schlüsselerzeugung. `Testing\Rsa` findet sie neben `php.exe` selbst.
