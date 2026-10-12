<?php

use EasySuite\Common\Oidc\EloquentUserProvisioner;

return [

    /*
    |--------------------------------------------------------------------------
    | Identity Provider (Auth-EasySuite)
    |--------------------------------------------------------------------------
    */
    'issuer' => env('EASYSUITE_ISSUER', 'https://auth.easysuite.ch'),
    'jwks_uri' => env('EASYSUITE_JWKS_URI'), // Default: <issuer>/.well-known/jwks.json

    // Dieses System als OAuth-Client (und als Resource Server: client_id = erwartete `aud`).
    'client_id' => env('EASYSUITE_CLIENT_ID'),
    'client_secret' => env('EASYSUITE_CLIENT_SECRET'),

    // Erlaubte Zeitabweichung bei exp/nbf/iat in Sekunden.
    'leeway' => 30,
    'jwks_cache_ttl' => 600,

    // Cache-Store für JWKS, Discovery, Revocation und S2S-Tokens (null = Standard-Store).
    // Bei mehreren App-Instanzen muss das ein gemeinsamer Store sein (Redis/DB).
    'cache_store' => env('EASYSUITE_CACHE_STORE'),

    // So lange (Sekunden) gelten widerrufene Sessions/Subjects in der lokalen Sperrliste.
    // Mindestens so lang wie die längste App-Session.
    'revocation_ttl' => 60 * 60 * 24 * 7,

    /*
    |--------------------------------------------------------------------------
    | Dieses System
    |--------------------------------------------------------------------------
    */
    'self' => [
        // Öffentliche Basis-URL dieses Systems. Sie ist `iss` der eigenen Events
        // und die erwartete `aud` von eingehenden Events.
        'url' => env('EASYSUITE_SELF_URL', env('APP_URL')),
    ],

    /*
    |--------------------------------------------------------------------------
    | Browser-Login (Authorization Code + PKCE)
    |--------------------------------------------------------------------------
    */
    'login' => [
        'enabled' => env('EASYSUITE_LOGIN_ENABLED', true),
        'route_prefix' => 'auth',
        'middleware' => ['web'],
        'redirect_uri' => env('EASYSUITE_REDIRECT_URI'), // Default: url('/auth/callback')
        'scopes' => ['openid', 'profile', 'email'],
        'guard' => null,

        // Definiert zusätzlich GET /login (Name `login`), das auf den Auth-Server weiterleitet,
        // damit Laravels `Authenticate`-Middleware funktioniert.
        'define_login_route' => true,

        'redirect_after_login' => '/',
        'redirect_after_logout' => '/',

        // Klasse, die einen lokalen User aus dem Profil erzeugt/aktualisiert.
        'provisioner' => EloquentUserProvisioner::class,
        'user_model' => env('EASYSUITE_USER_MODEL', 'App\\Models\\User'),
        'uuid_column' => 'uuid',      // lokale Spalte für `sub`
        'tenant_column' => 'tenant_id', // lokale Spalte für `tid` (null = nicht speichern)
    ],

    /*
    |--------------------------------------------------------------------------
    | Konsolen-Rollen (Orbis entscheidet, wer in die Konsole einer App darf)
    |--------------------------------------------------------------------------
    */
    'console_access' => [
        'fresh_seconds' => 60,   // so lange gilt eine Antwort von Orbis ohne neue Frage
        'stale_seconds' => 3600, // so lange gilt sie noch, wenn Orbis nicht erreichbar ist
    ],

    /*
    |--------------------------------------------------------------------------
    | Service-zu-Service
    |--------------------------------------------------------------------------
    | `audience` ist die client_id des Ziel-Systems in Auth.
    */
    'services' => [
        'auth' => ['url' => env('EASYSUITE_AUTH_URL', 'https://auth.easysuite.ch'),         'audience' => env('EASYSUITE_AUTH_AUDIENCE')],
        'orbis' => ['url' => env('EASYSUITE_ORBIS_URL', 'https://orbis.easysuite.ch'),       'audience' => env('EASYSUITE_ORBIS_AUDIENCE')],
        'security' => ['url' => env('EASYSUITE_SECURITY_URL', 'https://security.easysuite.ch'), 'audience' => env('EASYSUITE_SECURITY_AUDIENCE')],
        'billing' => ['url' => env('EASYSUITE_BILLING_URL', 'https://billing.easysuite.ch'),   'audience' => env('EASYSUITE_BILLING_AUDIENCE')],
    ],
    's2s' => [
        'timeout' => 10,
        'retries' => 2,
    ],

    /*
    |--------------------------------------------------------------------------
    | Events (Security Event Tokens)
    |--------------------------------------------------------------------------
    */
    'events' => [
        'enabled' => env('EASYSUITE_EVENTS_ENABLED', true),
        'route_prefix' => 's2s',

        // Eigener Signaturschlüssel (PEM-Inhalt ODER Dateipfad), nur nötig, wenn dieses System Events sendet.
        'signing_key' => env('EASYSUITE_EVENTS_SIGNING_KEY'),
        'signing_key_path' => env('EASYSUITE_EVENTS_SIGNING_KEY_PATH'),
        'publish_jwks' => env('EASYSUITE_EVENTS_PUBLISH_JWKS', true), // GET /.well-known/jwks.json mit dem eigenen Public Key

        // Scope, den der Sender im S2S-Token für das Event-POST anfordert.
        'send_scope' => 'events:send',

        // Aussteller, deren Events wir akzeptieren: issuer => jwks_uri
        'trusted_issuers' => json_decode((string) env('EASYSUITE_EVENTS_TRUSTED_ISSUERS', '{}'), true) ?: [
            // 'https://auth.easysuite.ch' => 'https://auth.easysuite.ch/.well-known/jwks.json',
        ],

        // Empfänger unserer Events:
        // ['audience' => 'https://security.easysuite.ch', 'endpoint' => 'https://security.easysuite.ch/s2s/events',
        //  's2s_audience' => '<client_id von Security>', 'events' => ['*']]
        'subscriptions' => json_decode((string) env('EASYSUITE_EVENTS_SUBSCRIPTIONS', '[]'), true) ?: [],

        'max_skew_seconds' => 300,
        'dedupe_ttl' => 60 * 60 * 24 * 7,
        'backoff' => [10, 60, 300, 1800, 7200, 43200], // Sekunden je Versuch, danach dead
        'builtin_handlers' => true, // session.revoked / user.disabled → lokale Sperrliste
    ],
];
