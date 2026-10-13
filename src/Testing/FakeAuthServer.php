<?php

namespace EasySuite\Common\Testing;

use DateTimeImmutable;
use EasySuite\Common\Jwt\Jwk;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;

/**
 * Test-Helfer: ein künstlicher Auth-Server mit eigenem RSA-Schlüssel.
 *
 *   $auth = FakeAuthServer::install();          // setzt Config + Http::fake (JWKS, Discovery, Token, UserInfo)
 *   $jwt  = $auth->accessToken(['scopes' => ['orbis:users.read'], 'tid' => 'tenant-1']);
 *   $this->withToken($jwt)->getJson('/api/...')->assertOk();
 */
class FakeAuthServer
{
    private string $privatePem;

    private string $publicPem;

    public readonly string $kid;

    /** @var array<string, mixed> */
    private array $loginClaims = [];

    /** @var array<string, mixed> */
    private array $profile = [];

    public function __construct(
        public readonly string $issuer = 'https://auth.test',
        public readonly string $clientId = 'test-client',
    ) {
        ['private' => $this->privatePem, 'public' => $this->publicPem] = Rsa::generate();
        $this->kid = Jwk::fromPublicPem($this->publicPem)['kid'];
    }

    /** Konfiguriert `easysuite.*` und registriert die HTTP-Fakes. */
    public static function install(string $issuer = 'https://auth.test', string $clientId = 'test-client'): self
    {
        $server = new self($issuer, $clientId);
        $server->configure();
        $server->fakeHttp();

        return $server;
    }

    public function configure(): void
    {
        config([
            'easysuite.issuer' => $this->issuer,
            'easysuite.jwks_uri' => null,
            'easysuite.client_id' => $this->clientId,
            'easysuite.client_secret' => 'test-secret',
        ]);
    }

    /** @var array<int, array<string, mixed>> */
    private array $extraKeys = [];

    private ?int $tokenEndpointFailure = null;

    private array $tokenEndpointError = ['error' => 'invalid_client'];

    public function jwks(): array
    {
        return ['keys' => [Jwk::fromPublicPem($this->publicPem), ...$this->extraKeys]];
    }

    /** Veröffentlicht zusätzlich den Schlüssel eines anderen Servers (Key-Rotation simulieren). */
    public function publishKeyOf(self $other): self
    {
        $this->extraKeys = array_merge($this->extraKeys, $other->jwks()['keys']);

        return $this;
    }

    /** Der Token-Endpoint antwortet ab jetzt mit diesem Fehlerstatus. */
    public function failTokenEndpoint(int $status = 401, string $error = 'invalid_client', ?string $description = null): self
    {
        $this->tokenEndpointFailure = $status;
        $this->tokenEndpointError = array_filter(['error' => $error, 'error_description' => $description]);

        return $this;
    }

    /** Access Token eines Users (idtyp=user). Mit `$claims` lassen sich alle Defaults überschreiben. */
    public function accessToken(array $claims = [], array $headers = []): string
    {
        return $this->sign($claims + [
            'iss' => $this->issuer,
            'sub' => 'user-1',
            'aud' => $this->clientId,
            'azp' => $this->clientId,
            'tid' => 'tenant-1',
            'sid' => 'session-1',
            'idtyp' => 'user',
            'scopes' => ['openid'],
            'iat' => time(),
            'nbf' => time(),
            'exp' => time() + 900,
            'jti' => bin2hex(random_bytes(8)),
        ], $headers);
    }

    /** Token einer App (client_credentials). */
    public function appToken(array $claims = [], array $headers = []): string
    {
        return $this->accessToken($claims + [
            'sub' => 'app-1',
            'azp' => 'app-1',
            'idtyp' => 'app',
            'sid' => null,
            'tid' => null,
        ], $headers);
    }

    public function logoutToken(array $claims = []): string
    {
        return $this->sign($claims + [
            'iss' => $this->issuer,
            'aud' => $this->clientId,
            'iat' => time(),
            'jti' => bin2hex(random_bytes(8)),
            'sid' => 'session-1',
            'sub' => 'user-1',
            'events' => ['http://schemas.openid.net/event/backchannel-logout' => new \stdClass],
        ]);
    }

    /** Ein SET dieses (fiktiven) Ausstellers, z. B. für Tests des Event-Empfangs. */
    public function set(array $events, string $audience, array $claims = []): string
    {
        return $this->sign($claims + [
            'iss' => $this->issuer,
            'aud' => $audience,
            'iat' => time(),
            'jti' => bin2hex(random_bytes(8)),
            'events' => $events,
        ], ['typ' => 'secevent+jwt']);
    }

    /** Der nächste Code-Tausch liefert ein Token mit diesen Claims und dieses UserInfo-Profil. */
    public function loginAs(array $claims = [], array $profile = []): self
    {
        $this->loginClaims = $claims;
        $this->profile = $profile;

        return $this;
    }

    public function fakeHttp(): void
    {
        $base = $this->issuer;

        Http::fake([
            "{$base}/.well-known/jwks.json" => fn () => Http::response($this->jwks()),

            "{$base}/.well-known/openid-configuration" => Http::response([
                'issuer' => $base,
                'authorization_endpoint' => "{$base}/oauth/authorize",
                'token_endpoint' => "{$base}/oauth/token",
                'userinfo_endpoint' => "{$base}/oidc/userinfo",
                'end_session_endpoint' => "{$base}/oidc/logout",
                'jwks_uri' => "{$base}/.well-known/jwks.json",
            ]),

            "{$base}/oauth/token" => function (Request $request) {
                if ($this->tokenEndpointFailure !== null) {
                    return Http::response($this->tokenEndpointError, $this->tokenEndpointFailure);
                }

                if ($request['grant_type'] === 'client_credentials') {
                    return Http::response([
                        'access_token' => $this->appToken([
                            'aud' => $request['audience'] ?? $this->clientId,
                            'sub' => $request['client_id'],
                            'azp' => $request['client_id'],
                            'scopes' => array_values(array_filter(explode(' ', (string) $request['scope']))),
                        ]),
                        'token_type' => 'Bearer',
                        'expires_in' => 900,
                    ]);
                }

                return Http::response([
                    'access_token' => $this->accessToken($this->loginClaims),
                    'refresh_token' => 'refresh-token',
                    'token_type' => 'Bearer',
                    'expires_in' => 900,
                ]);
            },

            "{$base}/oidc/userinfo" => fn () => Http::response($this->profile + [
                'sub' => $this->loginClaims['sub'] ?? 'user-1',
                'email' => 'jane@example.test',
                'name' => 'Jane Example',
            ]),
        ]);
    }

    /** Beliebiges JWT mit dem Schlüssel dieses Servers. `null`-Claims werden weggelassen. */
    public function sign(array $claims, array $headers = []): string
    {
        $config = Configuration::forAsymmetricSigner(
            new Sha256,
            InMemory::plainText($this->privatePem),
            InMemory::plainText($this->publicPem)
        );

        $builder = $config->builder()->withHeader('kid', $headers['kid'] ?? $this->kid);
        unset($headers['kid']);

        foreach ($headers as $name => $value) {
            $builder = $builder->withHeader($name, $value);
        }

        foreach (array_filter($claims, fn ($value) => $value !== null) as $name => $value) {
            $builder = match ($name) {
                'iss' => $builder->issuedBy($value),
                'sub' => $builder->relatedTo($value),
                'jti' => $builder->identifiedBy($value),
                'aud' => $builder->permittedFor(...(array) $value),
                'iat' => $builder->issuedAt($this->date($value)),
                'nbf' => $builder->canOnlyBeUsedAfter($this->date($value)),
                'exp' => $builder->expiresAt($this->date($value)),
                default => $builder->withClaim($name, $value),
            };
        }

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }

    private function date(int $timestamp): DateTimeImmutable
    {
        return (new DateTimeImmutable)->setTimestamp($timestamp);
    }
}
