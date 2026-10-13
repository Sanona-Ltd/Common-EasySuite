<?php

namespace EasySuite\Common\Tests\Feature;

use Dotenv\Dotenv;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

class PullEnvTest extends TestCase
{
    private string $file;

    protected function setUp(): void
    {
        parent::setUp();

        $this->file = sys_get_temp_dir().'/easysuite-env-'.bin2hex(random_bytes(4));
        file_put_contents($this->file, "INFISICAL_URL=https://inf.test\nINFISICAL_PROJECT_ID=proj-1\nINFISICAL_CLIENT_ID=cid\nINFISICAL_CLIENT_SECRET=csec\nINFISICAL_FOLDER=/orbis_easysuite\nOLD_ONLY=1\n");
    }

    protected function tearDown(): void
    {
        foreach ([$this->file, $this->file.'.previous', $this->file.'.tmp'] as $f) {
            @unlink($f);
        }

        parent::tearDown();
    }

    private function infisical(array $secrets, int $status = 200): void
    {
        Http::swap(new \Illuminate\Http\Client\Factory);
        Http::fake([
            'inf.test/api/v1/auth/universal-auth/login' => Http::response(['accessToken' => 'tok']),
            'inf.test/api/v3/secrets/raw*' => Http::response(['secrets' => array_map(fn ($k, $v) => ['secretKey' => $k, 'secretValue' => $v], array_keys($secrets), $secrets)], $status),
        ]);
    }

    public function test_it_writes_the_env_from_the_folder_and_keeps_what_is_needed_to_pull_again(): void
    {
        $hard = ['APP_KEY' => 'base64:ab+/=', 'APP_URL' => 'https://orbis.test', 'DB_PASSWORD' => 'p@ss $word"x\'y', 'JSON' => '{"a":"b c"}', 'EMPTY' => ''];
        $this->infisical($hard);

        $this->artisan('easysuite:env:pull', ['--file' => $this->file])->assertSuccessful();

        Http::assertSent(fn (Request $r) => str_contains($r->url(), '/secrets/raw') && $r['secretPath'] === '/orbis_easysuite' && $r['environment'] === 'prod' && $r['workspaceId'] === 'proj-1' && $r->hasHeader('Authorization', 'Bearer tok'));

        $written = Dotenv::parse(file_get_contents($this->file));
        $this->assertSame($hard, array_diff_key($written, array_flip(['INFISICAL_URL', 'INFISICAL_PROJECT_ID', 'INFISICAL_CLIENT_ID', 'INFISICAL_CLIENT_SECRET', 'INFISICAL_FOLDER'])));
        $this->assertSame('csec', $written['INFISICAL_CLIENT_SECRET']);
        $this->assertSame('/orbis_easysuite', $written['INFISICAL_FOLDER']);
        $this->assertArrayNotHasKey('OLD_ONLY', $written);
        $this->assertStringContainsString('OLD_ONLY=1', file_get_contents($this->file.'.previous'));
    }

    public function test_a_dry_run_changes_nothing_and_prints_no_values(): void
    {
        $this->infisical(['APP_KEY' => 'topsecretkey', 'APP_URL' => 'https://orbis.test']);
        $before = file_get_contents($this->file);

        $this->artisan('easysuite:env:pull', ['--file' => $this->file, '--dry-run' => true])
            ->expectsOutputToContain('OLD_ONLY')->doesntExpectOutputToContain('topsecretkey')->assertSuccessful();

        $this->assertSame($before, file_get_contents($this->file));
    }

    public function test_an_empty_or_unreachable_folder_leaves_the_env_alone(): void
    {
        $before = file_get_contents($this->file);

        $this->infisical([]);
        $this->artisan('easysuite:env:pull', ['--file' => $this->file])->expectsOutputToContain('APP_KEY')->assertFailed();

        $this->infisical([], 404);
        $this->artisan('easysuite:env:pull', ['--file' => $this->file])->expectsOutputToContain('cannot read')->assertFailed();

        Http::swap(new \Illuminate\Http\Client\Factory);
        Http::fake(['inf.test/*' => Http::response(['message' => 'no'], 401)]);
        $this->artisan('easysuite:env:pull', ['--file' => $this->file])->expectsOutputToContain('sign-in failed')->assertFailed();

        $this->assertSame($before, file_get_contents($this->file));
    }

    public function test_it_says_what_is_missing(): void
    {
        file_put_contents($this->file, "INFISICAL_URL=https://inf.test\n");

        $this->artisan('easysuite:env:pull', ['--file' => $this->file])->expectsOutputToContain('INFISICAL_CLIENT_ID')->assertFailed();
    }
}
