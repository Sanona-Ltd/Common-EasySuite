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

## Selbsttest

`php artisan easysuite:doctor` prüft aus Sicht des Systems: Einstellungen, Auth (Discovery, Schlüssel) und für jedes System, das es aufruft, ein echtes Token mit den nötigen Scopes sowie ob das System antwortet. Welche Scopes ein System braucht, steht in seiner `config/easysuite.php` unter `doctor.checks` (`service => [scopes]`). Ein System ohne Eintrag wird nur auf die Audience geprüft. Schlägt die Token-Anfrage fehl, nennt der Befehl (und jede `S2SException`) den Grund, den Auth angibt, und was zu tun ist: Scope in der App-Registrierung ergänzen, `client_credentials` freischalten, Client-ID/Secret prüfen, Audience prüfen.

## Konfiguration aus Infisical

`php artisan easysuite:env:pull` baut die `.env` des Systems aus seinem Infisical-Ordner (Secrets-API, Universal Auth). Vorher steht in der `.env` nur: `INFISICAL_URL`, `INFISICAL_PROJECT_ID`, `INFISICAL_ENVIRONMENT`, `INFISICAL_CLIENT_ID`, `INFISICAL_CLIENT_SECRET`, `INFISICAL_FOLDER` (z. B. `/orbis_easysuite`). Deploy-Schritt: `php artisan easysuite:env:pull && php artisan config:cache`. Die Infisical-Zugangsdaten bleiben in der neuen `.env`, die alte liegt als `.env.previous` daneben. `--dry-run` zeigt nur Schlüsselnamen (neu / geändert / nur in der alten Datei), nie Werte. Eine leere oder unlesbare Antwort lässt die `.env` unangetastet.

## Releases

Die Apps beziehen das Paket per Composer aus diesem Repo (`"easysuite/common": "^0.1"`, VCS-Quelle). Eine Änderung kommt erst an, wenn sie getaggt ist:

```
git tag -a v0.1.1 -m "…" && git push origin v0.1.1      # in Common
composer update easysuite/common                         # in jeder App, danach Tests und committen
```

Auf dem Server braucht Composer Lesezugriff auf das private Repo (Deploy-Key, oder `COMPOSER_AUTH` mit einem GitHub-Token: `{"github-oauth":{"github.com":"<token>"}}`).
