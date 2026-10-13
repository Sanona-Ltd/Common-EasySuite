<?php

namespace EasySuite\Common\S2S;

use EasySuite\Common\Oidc\OidcClient;
use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Http\Client\PendingRequest;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Str;

/**
 * Service-zu-Service-Aufrufe mit `client_credentials`. Die Tokens werden bis kurz vor Ablauf gecacht.
 *
 *   $orbis = app(Client::class)->request('orbis', ['orbis:users.read']);
 *   $roles = $orbis->get("/s2s/users/{$uuid}/roles")->throw()->json();
 */
class Client
{
    public function __construct(
        private readonly Http $http,
        private readonly Cache $cache,
        private readonly OidcClient $oidc,
    ) {}

    /** @param string[] $scopes */
    public function request(string $service, array $scopes = []): PendingRequest
    {
        $config = $this->service($service);

        return $this->http
            ->baseUrl(rtrim($config['url'], '/'))
            ->withToken($this->token($service, $scopes))
            ->acceptJson()
            ->withHeaders(['X-Request-Id' => request()?->header('X-Request-Id') ?: (string) Str::uuid()])
            ->timeout((int) config('easysuite.s2s.timeout'))
            ->retry(
                (int) config('easysuite.s2s.retries') + 1,
                200,
                fn ($exception) => $exception instanceof ConnectionException
                    || ($exception instanceof RequestException && $exception->response->serverError()),
                false
            );
    }

    /** @param string[] $scopes */
    public function token(string $service, array $scopes = []): string
    {
        $audience = $this->service($service)['audience'] ?? null;

        if (! $audience) {
            throw new S2SException("No audience configured for service '{$service}'.");
        }

        return $this->tokenForAudience($audience, $scopes);
    }

    /**
     * Token für ein Ziel, das nicht in `easysuite.services` steht (z. B. Event-Empfänger).
     *
     * @param  string[]  $scopes
     */
    public function tokenForAudience(string $audience, array $scopes = []): string
    {
        $key = $this->cacheKey($audience, $scopes);

        if ($cached = $this->cache->get($key)) {
            return $cached;
        }

        $response = $this->http->asForm()->timeout(10)->post($this->tokenEndpoint(), array_filter([
            'grant_type' => 'client_credentials',
            'client_id' => config('easysuite.client_id'),
            'client_secret' => config('easysuite.client_secret'),
            'scope' => implode(' ', $scopes),
            'audience' => $audience,
        ]));

        if ($response->failed() || ! $response->json('access_token')) {
            throw new S2SException($this->tokenFailure($audience, $scopes, $response));
        }

        $token = $response->json('access_token');
        $ttl = max(30, (int) $response->json('expires_in', 300) - 60);
        $this->cache->put($key, $token, $ttl);

        return $token;
    }

    /** Verwirft das gecachte Token, z. B. nach einem 401 des Ziel-Systems. */
    public function forget(string $service, array $scopes = []): void
    {
        $this->forgetAudience($this->service($service)['audience'] ?? '', $scopes);
    }

    public function forgetAudience(string $audience, array $scopes = []): void
    {
        $this->cache->forget($this->cacheKey($audience, $scopes));
    }

    /** What Auth said, and what to do about it: "HTTP 400" alone cost an afternoon. */
    private function tokenFailure(string $audience, array $scopes, $response): string
    {
        $error = (string) $response->json('error', '');
        $detail = trim($error.($response->json('error_description') ? ': '.$response->json('error_description') : '').($response->json('hint') ? ' ('.$response->json('hint').')' : ''));
        $hint = match ($error) {
            'invalid_scope' => 'A requested scope is not granted to this client: add it to the scopes of the app registration in Orbis (requested: '.($scopes ? implode(' ', $scopes) : 'none').').',
            'unauthorized_client', 'unsupported_grant_type' => 'This client may not use client_credentials: tick that grant type in the app registration in Orbis.',
            'invalid_client' => 'Client id or secret are not accepted: check EASYSUITE_CLIENT_ID and EASYSUITE_CLIENT_SECRET.',
            'invalid_target' => 'Auth does not know the audience: check the EASYSUITE_*_AUDIENCE of the target system.',
            default => null,
        };

        return "Could not obtain an S2S token for audience '{$audience}' (HTTP {$response->status()}".($detail !== '' ? ", {$detail}" : '').').'.($hint ? ' '.$hint : '');
    }

    private function tokenEndpoint(): string
    {
        return $this->oidc->endpoint('token_endpoint')
            ?? throw new S2SException('Discovery document has no token_endpoint.');
    }

    /** @return array{url: string, audience: ?string} */
    private function service(string $service): array
    {
        return config("easysuite.services.{$service}")
            ?? throw new S2SException("Unknown service '{$service}'.");
    }

    private function cacheKey(string $audience, array $scopes): string
    {
        sort($scopes);

        return 'easysuite:s2s-token:'.sha1(config('easysuite.client_id').'|'.$audience.'|'.implode(' ', $scopes));
    }
}
