<?php

namespace EasySuite\Common\Http\Middleware;

use Closure;
use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\TokenVerifier;
use EasySuite\Common\Oidc\RevokedSessions;
use EasySuite\Common\Support\Problem;
use EasySuite\Common\Support\TenantContext;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Prüft den Bearer-Token (Signatur, iss, aud = eigene client_id, Zeitfenster, Sperrliste).
 * Legt das Ergebnis als `easysuite.token` ins Request-Attribut und setzt den Tenant-Kontext.
 */
class RequireToken
{
    public const ATTRIBUTE = 'easysuite.token';

    public function __construct(
        private readonly TokenVerifier $verifier,
        private readonly RevokedSessions $revoked,
        private readonly TenantContext $tenant,
    ) {}

    public function handle(Request $request, Closure $next): Response
    {
        $jwt = $request->bearerToken();

        if (! $jwt) {
            return Problem::unauthorized('Missing bearer token.', null, 'invalid_request');
        }

        $issuer = config('easysuite.issuer');

        try {
            $token = $this->verifier->verify(
                $jwt,
                $issuer,
                config('easysuite.jwks_uri') ?: rtrim($issuer, '/').'/.well-known/jwks.json',
                config('easysuite.client_id'),
                config('easysuite.leeway'),
            );
        } catch (InvalidTokenException $e) {
            return Problem::unauthorized('Invalid token.');
        }

        if ($this->revoked->isSessionRevoked($token->sid())
            || $this->revoked->isSubjectRevoked($token->sub(), $token->issuedAt())) {
            return Problem::unauthorized('Token has been revoked.');
        }

        $request->attributes->set(self::ATTRIBUTE, $token);
        $this->tenant->set($token->tid());

        return $next($request);
    }
}
