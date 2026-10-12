<?php

namespace EasySuite\Common\Events;

use EasySuite\Common\Jwt\Jwk;
use EasySuite\Common\Support\Clock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use RuntimeException;

/** Signiert Security Event Tokens (RFC 8417) mit dem Schlüssel dieses Systems. */
class SetSigner
{
    public function __construct(private readonly Clock $clock) {}

    /**
     * @param  array<string, array<string, mixed>>  $events  Event-URI => Payload
     */
    public function sign(string $audience, array $events, ?string $tid = null, ?string $txn = null, ?string $jti = null): string
    {
        $privatePem = $this->privatePem();
        $config = Configuration::forAsymmetricSigner(
            new Sha256,
            InMemory::plainText($privatePem),
            InMemory::plainText($this->publicPem())
        );

        $builder = $config->builder()
            ->issuedBy(rtrim((string) config('easysuite.self.url'), '/'))
            ->permittedFor($audience)
            ->identifiedBy($jti ?? bin2hex(random_bytes(16)))
            ->issuedAt($this->clock->now())
            ->withHeader('typ', 'secevent+jwt')
            ->withHeader('kid', $this->keyId())
            ->withClaim('events', $events);

        if ($tid !== null) {
            $builder = $builder->withClaim('tid', $tid);
        }

        if ($txn !== null) {
            $builder = $builder->withClaim('txn', $txn);
        }

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }

    /**
     * Signs an arbitrary JWT (e.g. a policy bundle) with this system's key: `iss` = our URL, `iat` = now,
     * `kid` in the header. `aud` is required so a token can never be replayed at a system it was not meant for.
     *
     * @param  array<string, mixed>  $claims
     */
    public function signClaims(string $audience, array $claims): string
    {
        $config = Configuration::forAsymmetricSigner(
            new Sha256,
            InMemory::plainText($this->privatePem()),
            InMemory::plainText($this->publicPem())
        );

        $builder = $config->builder()
            ->withHeader('kid', $this->keyId())
            ->issuedBy(rtrim((string) config('easysuite.self.url'), '/'))
            ->permittedFor($audience)
            ->issuedAt($this->clock->now());

        foreach ($claims as $name => $value) {
            if (in_array($name, ['iss', 'aud', 'iat', 'exp', 'nbf', 'jti', 'sub'], true)) {
                continue; // the registered claims are set above, never from caller input
            }

            $builder = $builder->withClaim($name, $value);
        }

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }

    public function isConfigured(): bool
    {
        return (bool) (config('easysuite.events.signing_key') ?: config('easysuite.events.signing_key_path'));
    }

    public function publicPem(): string
    {
        $resource = openssl_pkey_get_private($this->privatePem());
        $details = $resource ? openssl_pkey_get_details($resource) : false;

        return $details['key'] ?? throw new RuntimeException('Events signing key is not a valid RSA private key.');
    }

    public function keyId(): string
    {
        return Jwk::fromPublicPem($this->publicPem())['kid'];
    }

    private function privatePem(): string
    {
        if ($pem = config('easysuite.events.signing_key')) {
            return str_replace('\n', "\n", $pem);
        }

        $path = config('easysuite.events.signing_key_path');

        if ($path && is_file($path)) {
            return (string) file_get_contents($path);
        }

        throw new RuntimeException('No events signing key configured (easysuite.events.signing_key[_path]).');
    }
}
