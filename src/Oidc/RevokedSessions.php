<?php

namespace EasySuite\Common\Oidc;

use Illuminate\Contracts\Cache\Repository as Cache;

/**
 * Lokale Sperrliste, gespeist durch Back-Channel-Logout und die Events
 * `session.revoked` / `user.disabled`. Wird von den Middlewares geprüft.
 */
class RevokedSessions
{
    public function __construct(
        private readonly Cache $cache,
        private readonly int $ttl,
    ) {}

    public function revokeSession(string $sid): void
    {
        $this->cache->put("easysuite:revoked:sid:{$sid}", time(), $this->ttl);
    }

    /** Sperrt alles, was für dieses Subject vor jetzt ausgestellt wurde. */
    public function revokeSubject(string $sub): void
    {
        $this->cache->put("easysuite:revoked:sub:{$sub}", time(), $this->ttl);
    }

    public function isSessionRevoked(?string $sid): bool
    {
        return $sid !== null && $this->cache->has("easysuite:revoked:sid:{$sid}");
    }

    /** @param int|null $issuedAt Ausstellungszeit des Tokens bzw. Login-Zeit der Session */
    public function isSubjectRevoked(?string $sub, ?int $issuedAt): bool
    {
        if ($sub === null) {
            return false;
        }

        $revokedAt = $this->cache->get("easysuite:revoked:sub:{$sub}");

        return $revokedAt !== null && ($issuedAt === null || $issuedAt <= $revokedAt);
    }
}
