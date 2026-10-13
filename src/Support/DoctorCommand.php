<?php

namespace EasySuite\Common\Support;

use EasySuite\Common\Oidc\OidcClient;
use EasySuite\Common\S2S\Client;
use EasySuite\Common\S2S\S2SException;
use Illuminate\Console\Command;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

/**
 * Checks from this system's own point of view whether it is wired to the others: its settings, Auth (discovery, keys),
 * and for every system it talks to a real token with the scopes it needs, plus whether that system answers.
 * Which scopes a system needs is its own business: `easysuite.doctor.checks` maps service => scopes.
 *
 *   php artisan easysuite:doctor
 */
class DoctorCommand extends Command
{
    protected $signature = 'easysuite:doctor {--only=* : Only these services (orbis, billing, ...)}';

    protected $description = 'Checks the connection of this system to Auth and the other EasySuite systems.';

    private int $failed = 0;

    public function handle(Client $s2s, OidcClient $oidc): int
    {
        $this->line('');
        $this->line('Settings');
        $this->check('EASYSUITE_ISSUER', (bool) config('easysuite.issuer'), 'not set');
        $this->check('EASYSUITE_CLIENT_ID', (bool) config('easysuite.client_id'), 'not set: the id of this system\'s app registration in Orbis');
        $this->check('EASYSUITE_CLIENT_SECRET', (bool) config('easysuite.client_secret'), 'not set: shown once when the app was registered, or rotate it in Orbis');
        $this->check('EASYSUITE_SELF_URL', (bool) config('easysuite.self.url'), 'not set');

        $this->line('');
        $this->line('Auth ('.config('easysuite.issuer').')');

        try {
            $oidc->discovery();
            $this->check('discovery document', true);
        } catch (\Throwable $e) {
            $this->check('discovery document', false, 'not reachable: '.$e->getMessage());
        }

        try {
            $keys = Http::timeout(10)->get($oidc->jwksUri())->throw()->json('keys', []);
            $this->check('signing keys (JWKS)', $keys !== [], 'the key set is empty');
        } catch (\Throwable $e) {
            $this->check('signing keys (JWKS)', false, 'not reachable: '.$e->getMessage());
        }

        $wanted = (array) config('easysuite.doctor.checks', []);
        $only = array_filter((array) $this->option('only'));

        foreach ((array) config('easysuite.services', []) as $service => $config) {
            if (($only && ! in_array($service, $only, true)) || rtrim((string) ($config['url'] ?? ''), '/') === rtrim((string) config('easysuite.self.url'), '/')) {
                continue;
            }

            $needed = array_key_exists($service, $wanted);
            $this->line('');
            $this->line(ucfirst($service).' ('.($config['url'] ?? '?').')');

            if (blank($config['audience'] ?? null)) {
                $needed
                    ? $this->check('audience', false, 'EASYSUITE_'.strtoupper($service).'_AUDIENCE is not set: the client id of '.ucfirst($service).' (it is in the .env of that system)')
                    : $this->line('  –    not configured (fine if this system does not call '.ucfirst($service).')');

                continue;
            }

            $scopes = (array) ($wanted[$service] ?? []);

            try {
                $s2s->forget($service, $scopes);
                $s2s->token($service, $scopes);
                $this->check('token'.($scopes ? ' ('.implode(' ', $scopes).')' : ''), true);
            } catch (S2SException|ConnectionException $e) {
                $this->check('token'.($scopes ? ' ('.implode(' ', $scopes).')' : ''), false, $e->getMessage());

                continue;
            }

            try {
                Http::timeout(10)->get(rtrim($config['url'], '/').'/up');
                $this->check('system answers', true);
            } catch (ConnectionException $e) {
                $this->check('system answers', false, 'not reachable: '.$e->getMessage());
            }
        }

        $this->line('');
        $this->line($this->failed === 0 ? 'Everything checked is fine.' : "{$this->failed} problem(s), see above.");

        return $this->failed === 0 ? self::SUCCESS : self::FAILURE;
    }

    private function check(string $what, bool $ok, string $problem = ''): void
    {
        $ok || $this->failed++;
        $this->line(($ok ? '  OK   ' : '  FAIL ').$what.($ok ? '' : ': '.$problem));
    }
}
