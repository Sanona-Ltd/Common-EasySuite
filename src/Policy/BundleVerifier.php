<?php

namespace EasySuite\Common\Policy;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\TokenVerifier;

/**
 * Prüft ein Policy-Bundle von Security (siehe docs/architecture/04-policy-sync.md): ein RS256-signiertes JWT
 * mit `iss` = Security, `aud` = dieses System, `tid`, `version`, `policies`, `named_locations`.
 * Ein ungültiges Bundle wird komplett verworfen, es gibt keinen Teil-Import.
 */
class BundleVerifier
{
    public function __construct(private readonly TokenVerifier $verifier) {}

    /**
     * @return array{tid: string, version: int, issued_at: int, policies: array<int, array<string, mixed>>, named_locations: array<int, array<string, mixed>>}
     */
    public function verify(string $jws, string $expectedTenantId): array
    {
        $issuer = rtrim((string) config('easysuite.services.security.url'), '/');

        $token = $this->verifier->verify(
            $jws,
            $issuer,
            config('easysuite.policy.jwks_uri') ?: $issuer.'/.well-known/jwks.json',
            rtrim((string) config('easysuite.self.url'), '/'),
            (int) config('easysuite.leeway'),
            requireExp: false,
        );

        $version = $token->claim('version');
        $policies = $token->claim('policies');
        $locations = $token->claim('named_locations', []);

        if ($token->tid() !== $expectedTenantId) {
            throw new InvalidTokenException('Policy bundle is for a different tenant.');
        }

        if (! is_int($version) || $version < 1 || ! is_array($policies) || ! is_array($locations) || $token->issuedAt() === null) {
            throw new InvalidTokenException('Malformed policy bundle.');
        }

        return [
            'tid' => $expectedTenantId,
            'version' => $version,
            'issued_at' => $token->issuedAt(),
            'policies' => array_values($policies),
            'named_locations' => array_values($locations),
        ];
    }
}
