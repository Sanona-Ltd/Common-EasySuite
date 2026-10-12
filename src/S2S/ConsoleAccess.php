<?php

namespace EasySuite\Common\S2S;

use Illuminate\Contracts\Cache\Repository as Cache;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Http\Client\RequestException;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Log;

/**
 * Wer darf in die Konsole einer App (Security, Billing, …)? Das entscheidet Orbis (`GET /s2s/users/{sub}/access`,
 * Scope `orbis:users.read`), die App fragt nur. Die Antwort gilt kurz (`fresh_seconds`), damit eine Änderung bald greift.
 * Ist Orbis nicht erreichbar, gilt die letzte bekannte Antwort noch bis `stale_seconds`; ohne eine solche: kein Zugriff.
 *
 *   $role = app(ConsoleAccess::class)->role('security', $user->uuid);   // 'admin' | 'reader' | null
 */
class ConsoleAccess
{
    private const ROLES = ['admin', 'reader'];

    public function __construct(private readonly Client $s2s, private readonly Cache $cache) {}

    /** @return 'admin'|'reader'|null */
    public function role(string $app, string $uuid): ?string
    {
        return $this->access($uuid)[$app] ?? null;
    }

    /** @return array<string, ?string> */
    public function access(string $uuid): array
    {
        $key = 'easysuite:console-access:'.$uuid;
        $known = $this->cache->get($key);

        if (is_array($known) && Carbon::now()->getTimestamp() - $known['at'] < (int) config('easysuite.console_access.fresh_seconds', 60)) {
            return $known['access'];
        }

        try {
            $response = $this->s2s->request('orbis', ['orbis:users.read'])->get('/s2s/users/'.rawurlencode($uuid).'/access');

            // Orbis does not know the user: no access (and no point asking again for a moment).
            if ($response->status() === 404) {
                $access = [];
            } else {
                $response->throw();
                $access = $this->clean((array) $response->json('access', []));
            }
        } catch (RequestException|ConnectionException|S2SException $e) {
            if (is_array($known) && Carbon::now()->getTimestamp() - $known['at'] < (int) config('easysuite.console_access.stale_seconds', 3600)) {
                Log::warning('Orbis not reachable, using the last known console access', ['error' => $e->getMessage()]);

                return $known['access'];
            }

            Log::error('Orbis not reachable, no console access', ['error' => $e->getMessage()]);

            return [];
        }

        $this->cache->put($key, ['at' => Carbon::now()->getTimestamp(), 'access' => $access], (int) config('easysuite.console_access.stale_seconds', 3600));

        return $access;
    }

    /** Forgets what is known about a user, so the next request asks Orbis again. */
    public function forget(string $uuid): void
    {
        $this->cache->forget('easysuite:console-access:'.$uuid);
    }

    /** @param array<string, mixed> $access @return array<string, ?string> */
    private function clean(array $access): array
    {
        return array_map(fn ($role) => in_array($role, self::ROLES, true) ? $role : null, $access);
    }
}
