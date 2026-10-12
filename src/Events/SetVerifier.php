<?php

namespace EasySuite\Common\Events;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\TokenVerifier;

/** Prüft eingehende SETs: vertrauter Aussteller, Signatur, aud = dieses System, typ, iat-Abweichung. */
class SetVerifier
{
    public function __construct(private readonly TokenVerifier $verifier) {}

    /** @return ReceivedEvent[] */
    public function verify(string $jwt): array
    {
        $issuer = (string) ($this->verifier->unverifiedClaims($jwt)['iss'] ?? '');
        $trusted = (array) config('easysuite.events.trusted_issuers');

        if (! isset($trusted[$issuer])) {
            throw new InvalidTokenException('Untrusted event issuer.');
        }

        $token = $this->verifier->verify(
            $jwt,
            $issuer,
            $trusted[$issuer],
            rtrim((string) config('easysuite.self.url'), '/'),
            (int) config('easysuite.events.max_skew_seconds'),
            requireExp: false,
        );

        if ($token->header('typ') !== 'secevent+jwt') {
            throw new InvalidTokenException('Not a security event token.');
        }

        $iat = $token->issuedAt();

        if ($iat === null || abs(time() - $iat) > (int) config('easysuite.events.max_skew_seconds')) {
            throw new InvalidTokenException('Event is outside the accepted time window.');
        }

        if ($token->jti() === null) {
            throw new InvalidTokenException('Event has no jti.');
        }

        $events = [];
        foreach ((array) $token->claim('events', []) as $uri => $payload) {
            $events[] = new ReceivedEvent(
                type: (string) $uri,
                payload: (array) $payload,
                tid: $token->tid(),
                jti: $token->jti(),
                txn: $token->claim('txn'),
                issuer: $issuer,
                issuedAt: $iat,
            );
        }

        return $events;
    }
}
