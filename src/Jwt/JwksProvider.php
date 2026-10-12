<?php

namespace EasySuite\Common\Jwt;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\Factory as Http;
use Throwable;

/**
 * Lädt und cacht JWKS. Bei unbekanntem `kid` wird höchstens einmal pro Minute neu geladen
 * (Schutz gegen Token-Floods mit erfundenen kids).
 */
class JwksProvider
{
    public function __construct(
        private readonly Http $http,
        private readonly Cache $cache,
        private readonly int $ttl = 600,
    ) {}

    /** @var array<string, \Closure(): array<string, string>> */
    private array $local = [];

    /**
     * Keys of this very system (Auth verifies tokens it issued itself): served from memory instead of an HTTP
     * round trip to its own JWKS endpoint.
     *
     * @param  \Closure(): array<string, string>  $keys  kid => PEM
     */
    public function useLocalSource(string $uri, \Closure $keys): void
    {
        $this->local[$uri] = $keys;
    }

    /** @return array<string, string> kid => PEM */
    public function keys(string $uri): array
    {
        if (isset($this->local[$uri])) {
            return ($this->local[$uri])();
        }

        return $this->cache->get($this->key($uri)) ?? $this->fetch($uri);
    }

    public function pemFor(string $uri, ?string $kid): string
    {
        $keys = $this->keys($uri);

        if ($pem = $this->match($keys, $kid)) {
            return $pem;
        }

        if (! isset($this->local[$uri]) && $this->cache->add($this->key($uri).':refresh', 1, 60)) {
            $keys = $this->fetch($uri);

            if ($pem = $this->match($keys, $kid)) {
                return $pem;
            }
        }

        throw new InvalidTokenException('Unknown signing key.');
    }

    public function forget(string $uri): void
    {
        $this->cache->forget($this->key($uri));
    }

    /** @return array<string, string> */
    private function fetch(string $uri): array
    {
        try {
            $jwks = $this->http->timeout(5)->retry(2, 200, null, false)->get($uri)->throw()->json('keys');
        } catch (Throwable $e) {
            $stale = $this->cache->get($this->key($uri).':stale');

            if (is_array($stale)) {
                return $stale;
            }

            throw new InvalidTokenException('JWKS could not be loaded.', 0, $e);
        }

        $keys = [];
        foreach ((array) $jwks as $jwk) {
            if (($jwk['kty'] ?? null) !== 'RSA' || (isset($jwk['use']) && $jwk['use'] !== 'sig')) {
                continue;
            }
            $keys[$jwk['kid'] ?? Jwk::thumbprint($jwk)] = Jwk::toPem($jwk);
        }

        if ($keys === []) {
            throw new InvalidTokenException('JWKS contains no usable signing keys.');
        }

        $this->cache->put($this->key($uri), $keys, $this->ttl);
        $this->cache->put($this->key($uri).':stale', $keys, 86400);

        return $keys;
    }

    /** @param array<string, string> $keys */
    private function match(array $keys, ?string $kid): ?string
    {
        if ($kid !== null) {
            return $keys[$kid] ?? null;
        }

        return count($keys) === 1 ? reset($keys) : null;
    }

    private function key(string $uri): string
    {
        return 'easysuite:jwks:'.sha1($uri);
    }
}
