<?php

namespace EasySuite\Common\Jwt;

/**
 * Ein geprüftes JWT (Signatur, iss, aud, Zeitfenster sind bereits validiert).
 */
final class VerifiedToken
{
    /**
     * @param  array<string, mixed>  $claims  Zeit-Claims (exp, iat, nbf) als Unix-Timestamp
     * @param  array<string, mixed>  $headers
     */
    public function __construct(
        private readonly array $claims,
        private readonly array $headers = [],
    ) {}

    public function claim(string $name, mixed $default = null): mixed
    {
        return $this->claims[$name] ?? $default;
    }

    /** @return array<string, mixed> */
    public function claims(): array
    {
        return $this->claims;
    }

    public function header(string $name, mixed $default = null): mixed
    {
        return $this->headers[$name] ?? $default;
    }

    public function sub(): ?string
    {
        return $this->claim('sub');
    }

    public function tid(): ?string
    {
        return $this->claim('tid');
    }

    public function sid(): ?string
    {
        return $this->claim('sid');
    }

    public function jti(): ?string
    {
        return $this->claim('jti');
    }

    public function azp(): ?string
    {
        return $this->claim('azp');
    }

    public function issuer(): ?string
    {
        return $this->claim('iss');
    }

    public function issuedAt(): ?int
    {
        return $this->claim('iat');
    }

    public function expiresAt(): ?int
    {
        return $this->claim('exp');
    }

    /** Akzeptiert sowohl `scope` (RFC 9068, String) als auch `scopes` (Array, heutiges Auth-Format). */
    public function scopes(): array
    {
        $scopes = $this->claim('scopes', []);
        $scope = $this->claim('scope');

        if (is_string($scope) && $scope !== '') {
            $scopes = array_merge((array) $scopes, preg_split('/\s+/', trim($scope)));
        }

        return array_values(array_unique((array) $scopes));
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes(), true);
    }

    /** `user` (delegiert) oder `app` (client_credentials). Ohne `idtyp`: sub == azp bedeutet app. */
    public function type(): string
    {
        $type = $this->claim('idtyp');

        if (in_array($type, ['user', 'app'], true)) {
            return $type;
        }

        return $this->sub() !== null && $this->sub() === $this->azp() ? 'app' : 'user';
    }

    public function isUser(): bool
    {
        return $this->type() === 'user';
    }

    public function isApp(): bool
    {
        return $this->type() === 'app';
    }

    public function isSaasAdmin(): bool
    {
        return $this->claim('saas_admin') === true;
    }

    /** @return string[] */
    public function amr(): array
    {
        return array_values((array) $this->claim('amr', []));
    }

    public function acr(): ?string
    {
        return $this->claim('acr');
    }

    public function authTime(): ?int
    {
        return $this->claim('auth_time');
    }

    public function hasMfa(): bool
    {
        return $this->acr() === 'mfa' || in_array('mfa', $this->amr(), true);
    }
}
