<?php

namespace EasySuite\Common\Jwt;

use DateInterval;
use DateTimeInterface;
use EasySuite\Common\Support\Clock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Validator;
use Throwable;

/**
 * Prüft RS256-JWTs gegen ein JWKS. Der Algorithmus ist fest RS256, ein `alg` aus dem Header
 * wird nie übernommen.
 */
class TokenVerifier
{
    public function __construct(
        private readonly JwksProvider $jwks,
        private readonly Clock $clock,
        private readonly int $defaultLeeway = 30,
    ) {}

    /**
     * Claims OHNE Prüfung. Nur dazu da, den passenden Aussteller/Schlüssel auszuwählen,
     * niemals als Vertrauensgrundlage verwenden.
     *
     * @return array<string, mixed>
     */
    public function unverifiedClaims(string $jwt): array
    {
        try {
            $token = (new Parser(new JoseEncoder))->parse($jwt);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Malformed token.', 0, $e);
        }

        return $token instanceof UnencryptedToken ? $token->claims()->all() : [];
    }

    public function verify(
        string $jwt,
        string $issuer,
        string $jwksUri,
        ?string $audience = null,
        ?int $leeway = null,
        bool $requireExp = true,
    ): VerifiedToken {
        try {
            $token = (new Parser(new JoseEncoder))->parse($jwt);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Malformed token.', 0, $e);
        }

        if (! $token instanceof UnencryptedToken) {
            throw new InvalidTokenException('Unsupported token type.');
        }

        if ($token->headers()->get('alg') !== 'RS256') {
            throw new InvalidTokenException('Unsupported signing algorithm.');
        }

        if ($requireExp && ! $token->claims()->has('exp')) {
            throw new InvalidTokenException('Token has no expiry.');
        }

        $pem = $this->jwks->pemFor($jwksUri, $token->headers()->get('kid'));

        $constraints = [
            new SignedWith(new Sha256, InMemory::plainText($pem)),
            new IssuedBy($issuer),
            new LooseValidAt($this->clock, new DateInterval('PT'.($leeway ?? $this->defaultLeeway).'S')),
        ];

        if ($audience !== null) {
            $constraints[] = new PermittedFor($audience);
        }

        try {
            (new Validator)->assert($token, ...$constraints);
        } catch (Throwable $e) {
            throw new InvalidTokenException('Token validation failed: '.$e->getMessage(), 0, $e);
        }

        $claims = [];
        foreach ($token->claims()->all() as $name => $value) {
            $claims[$name] = $value instanceof DateTimeInterface ? $value->getTimestamp() : $value;
        }

        return new VerifiedToken($claims, $token->headers()->all());
    }
}
