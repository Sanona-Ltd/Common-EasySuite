<?php

namespace EasySuite\Common\Oidc;

use EasySuite\Common\Jwt\InvalidTokenException;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use RuntimeException;

/** Spricht mit dem Auth-Server: Discovery, Authorize-URL, Code-Tausch, UserInfo. */
class OidcClient
{
    public function __construct(
        private readonly Http $http,
        private readonly Cache $cache,
    ) {}

    public function issuer(): string
    {
        return rtrim((string) config('easysuite.issuer'), '/');
    }

    public function jwksUri(): string
    {
        return config('easysuite.jwks_uri') ?: $this->issuer().'/.well-known/jwks.json';
    }

    public function redirectUri(): string
    {
        // Aus der konfigurierten Basis-URL, nicht aus dem Host-Header des Requests.
        return config('easysuite.login.redirect_uri')
            ?: rtrim((string) config('easysuite.self.url'), '/').'/'.trim(config('easysuite.login.route_prefix'), '/').'/callback';
    }

    /** @return array<string, mixed> */
    public function discovery(): array
    {
        return $this->cache->remember('easysuite:discovery:'.sha1($this->issuer()), 3600, function () {
            $document = $this->http->timeout(5)->retry(2, 200, null, false)
                ->get($this->issuer().'/.well-known/openid-configuration')
                ->throw()
                ->json();

            if (rtrim((string) ($document['issuer'] ?? ''), '/') !== $this->issuer()) {
                throw new RuntimeException('Discovery issuer does not match the configured issuer.');
            }

            return $document;
        });
    }

    public function endpoint(string $name): ?string
    {
        return $this->discovery()[$name] ?? null;
    }

    public function authorizationUrl(string $state, string $nonce, string $codeChallenge, array $extra = []): string
    {
        $query = http_build_query([
            'response_type' => 'code',
            'client_id' => config('easysuite.client_id'),
            'redirect_uri' => $this->redirectUri(),
            'scope' => implode(' ', config('easysuite.login.scopes')),
            'state' => $state,
            'nonce' => $nonce,
            'code_challenge' => $codeChallenge,
            'code_challenge_method' => 'S256',
        ] + $extra, '', '&', PHP_QUERY_RFC3986);

        return $this->requiredEndpoint('authorization_endpoint').'?'.$query;
    }

    /** @return array<string, mixed> */
    public function exchangeCode(string $code, string $codeVerifier): array
    {
        $response = $this->http->asForm()->timeout(10)->post($this->requiredEndpoint('token_endpoint'), [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri(),
            'client_id' => config('easysuite.client_id'),
            'client_secret' => config('easysuite.client_secret'),
            'code_verifier' => $codeVerifier,
        ]);

        if ($response->failed() || ! $response->json('access_token')) {
            throw new InvalidTokenException('Authorization code exchange failed.');
        }

        return $response->json();
    }

    /** @return array<string, mixed> */
    public function userinfo(string $accessToken): array
    {
        $endpoint = $this->endpoint('userinfo_endpoint');

        if (! $endpoint) {
            return [];
        }

        $response = $this->http->withToken($accessToken)->acceptJson()->timeout(5)->get($endpoint);

        return $response->successful() ? (array) $response->json() : [];
    }

    private function requiredEndpoint(string $name): string
    {
        return $this->endpoint($name) ?? throw new RuntimeException("Discovery document has no {$name}.");
    }
}
