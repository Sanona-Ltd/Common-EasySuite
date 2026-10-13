<?php

namespace EasySuite\Common\Support;

use Dotenv\Dotenv;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Http;

/**
 * Builds the .env of this system from its Infisical folder, so no secret has to be kept on the server by hand.
 *
 * The one thing the .env needs beforehand are the Infisical settings (a machine identity that may read the folder):
 *
 *   INFISICAL_URL=https://…  INFISICAL_PROJECT_ID=…  INFISICAL_ENVIRONMENT=prod
 *   INFISICAL_CLIENT_ID=…    INFISICAL_CLIENT_SECRET=…  INFISICAL_FOLDER=/orbis_easysuite
 *
 * `php artisan easysuite:env:pull && php artisan config:cache` is then the deploy step. The Infisical settings are kept
 * in the new .env, the previous file stays as .env.previous. Values are never printed.
 */
class PullEnvCommand extends Command
{
    protected $signature = 'easysuite:env:pull
                            {--folder= : Infisical folder (default INFISICAL_FOLDER of the .env)}
                            {--file= : Target file (default .env of the application)}
                            {--dry-run : Only show which keys would be added, changed or removed}';

    protected $description = 'Writes the .env of this system from its Infisical folder.';

    private const BOOTSTRAP = ['INFISICAL_URL', 'INFISICAL_PROJECT_ID', 'INFISICAL_ENVIRONMENT', 'INFISICAL_CLIENT_ID', 'INFISICAL_CLIENT_SECRET', 'INFISICAL_FOLDER'];

    public function handle(): int
    {
        $file = (string) ($this->option('file') ?: base_path('.env'));
        $current = is_file($file) ? Dotenv::parse((string) file_get_contents($file)) : [];

        // Read from the file, not from config(): the config may be cached from an older .env.
        $setting = fn (string $key, ?string $default = null) => $current[$key] ?? (getenv($key) ?: $default);

        $folder = (string) ($this->option('folder') ?: $setting('INFISICAL_FOLDER'));
        $base = rtrim((string) $setting('INFISICAL_URL', 'https://app.infisical.com'), '/');
        $missing = array_filter(['INFISICAL_PROJECT_ID', 'INFISICAL_CLIENT_ID', 'INFISICAL_CLIENT_SECRET'], fn ($key) => ! $setting($key));

        if ($missing !== [] || $folder === '') {
            $this->error('Missing in the .env: '.implode(', ', [...$missing, ...($folder === '' ? ['INFISICAL_FOLDER'] : [])]).'.');

            return self::FAILURE;
        }

        $login = Http::acceptJson()->post($base.'/api/v1/auth/universal-auth/login', ['clientId' => $setting('INFISICAL_CLIENT_ID'), 'clientSecret' => $setting('INFISICAL_CLIENT_SECRET')]);

        if (! $login->successful() || ! $login->json('accessToken')) {
            $this->error("Infisical sign-in failed ({$login->status()}): check INFISICAL_URL, INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET.");

            return self::FAILURE;
        }

        $response = Http::acceptJson()->withToken($login->json('accessToken'))->get($base.'/api/v3/secrets/raw', [
            'workspaceId' => $setting('INFISICAL_PROJECT_ID'), 'environment' => $setting('INFISICAL_ENVIRONMENT', 'prod'), 'secretPath' => $folder,
        ]);

        if (! $response->successful()) {
            $this->error("Infisical: cannot read {$folder} ({$response->status()}): ".($response->json('message') ?? 'is the folder there and the identity allowed to read it?'));

            return self::FAILURE;
        }

        $values = collect($response->json('secrets', []))->pluck('secretValue', 'secretKey')->map(fn ($v) => (string) $v)->all();

        // Never replace a working .env with an empty or broken one.
        if ($values === [] || ! isset($values['APP_KEY'], $values['APP_URL'])) {
            $this->error("{$folder} holds no APP_KEY/APP_URL: the .env is left as it is.");

            return self::FAILURE;
        }

        // Keep what is needed to pull again, unless the folder sets it itself.
        foreach (self::BOOTSTRAP as $key) {
            if (! isset($values[$key]) && ($v = $setting($key)) !== null) {
                $values[$key] = (string) $v;
            }
        }

        $values['INFISICAL_FOLDER'] ??= $folder;
        $text = $this->render($values);

        if (Dotenv::parse($text) !== $values) {
            $this->error('A value cannot be written to a .env without changing it. Nothing was written.');

            return self::FAILURE;
        }

        $added = array_keys(array_diff_key($values, $current));
        $removed = array_keys(array_diff_key($current, $values));
        $changed = array_keys(array_filter($values, fn ($v, $k) => isset($current[$k]) && $current[$k] !== $v, ARRAY_FILTER_USE_BOTH));

        $this->components->info(($this->option('dry-run') ? '[dry run] ' : '').count($values)." keys from {$folder}: ".count($added).' new, '.count($changed).' changed, '.count($removed).' only in the old file (dropped)');

        foreach (['+' => $added, '~' => $changed, '-' => $removed] as $mark => $keys) {
            foreach ($keys as $key) {
                $this->line("   {$mark} {$key}");
            }
        }

        if ($removed !== []) {
            $this->line('Keys marked "-" are not in Infisical (DB_*, MAIL_* ...?): add them there, or the system loses them.');
        }

        if ($this->option('dry-run')) {
            return self::SUCCESS;
        }

        if (is_file($file)) {
            copy($file, $file.'.previous');
            @chmod($file.'.previous', 0600);
        }

        $tmp = $file.'.tmp';
        file_put_contents($tmp, $text);
        @chmod($tmp, 0600);
        rename($tmp, $file);

        $this->line("Written {$file}. Now: php artisan config:cache (and a worker restart if one is running).");

        return self::SUCCESS;
    }

    /** @param  array<string, string>  $values */
    private function render(array $values): string
    {
        $lines = ['# Generated by easysuite:env:pull from Infisical. Change values there, not here.'];

        foreach ($values as $key => $value) {
            $lines[] = $key.'='.$this->quote($value);
        }

        return implode("\n", $lines)."\n";
    }

    private function quote(string $value): string
    {
        if (preg_match('/^[A-Za-z0-9_.:\/@+,-]*$/', $value)) {
            return $value;
        }

        if (! str_contains($value, "'") && ! preg_match('/[\r\n]/', $value)) {
            return "'{$value}'";
        }

        return '"'.str_replace(['\\', '"', '$', "\r", "\n"], ['\\\\', '\\"', '\\$', '\\r', '\\n'], $value).'"';
    }
}
