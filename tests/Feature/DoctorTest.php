<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\S2S\Client;
use EasySuite\Common\S2S\S2SException;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

class DoctorTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config([
            'easysuite.client_id' => 'my-client',
            'easysuite.client_secret' => 'my-secret',
            'easysuite.services.orbis' => ['url' => 'https://orbis.test', 'audience' => 'orbis-client'],
            'easysuite.services.billing' => ['url' => 'https://billing.test', 'audience' => null],
            'easysuite.doctor.checks' => ['orbis' => ['orbis:users.read']],
        ]);

        Http::fake(['https://orbis.test/*' => Http::response('ok')]);
    }

    public function test_everything_in_order_is_reported_as_fine_and_the_token_asks_for_the_needed_scopes(): void
    {
        $this->artisan('easysuite:doctor')
            ->expectsOutputToContain('OK   token (orbis:users.read)')
            ->expectsOutputToContain('OK   system answers')
            ->expectsOutputToContain('not configured (fine if this system does not call Billing)')
            ->expectsOutputToContain('Everything checked is fine.')
            ->assertSuccessful();

        Http::assertSent(fn (Request $r) => str_ends_with($r->url(), '/oauth/token') && $r['scope'] === 'orbis:users.read' && $r['audience'] === 'orbis-client');
    }

    public function test_a_missing_audience_of_a_system_that_is_needed_is_named(): void
    {
        config(['easysuite.services.orbis.audience' => null]);

        $this->artisan('easysuite:doctor')
            ->expectsOutputToContain('FAIL audience: EASYSUITE_ORBIS_AUDIENCE is not set')
            ->assertFailed();
    }

    public function test_a_refused_scope_says_which_one_and_where_to_fix_it(): void
    {
        $this->auth->failTokenEndpoint(400, 'invalid_scope', 'The requested scope is invalid, unknown, or malformed');

        $this->artisan('easysuite:doctor')
            ->expectsOutputToContain('add it to the scopes of the app registration in Orbis (requested: orbis:users.read)')
            ->assertFailed();
    }

    public function test_missing_settings_are_listed(): void
    {
        config(['easysuite.client_secret' => null]);

        $this->artisan('easysuite:doctor', ['--only' => ['none']])
            ->expectsOutputToContain('FAIL EASYSUITE_CLIENT_SECRET')
            ->assertFailed();
    }

    public function test_the_token_error_carries_what_auth_said(): void
    {
        $client = app(Client::class);

        foreach ([
            [400, 'unauthorized_client', 'tick that grant type'],
            [401, 'invalid_client', 'EASYSUITE_CLIENT_SECRET'],
            [400, 'invalid_target', 'EASYSUITE_*_AUDIENCE'],
        ] as [$status, $error, $hint]) {
            $this->auth->failTokenEndpoint($status, $error);
            $client->forget('orbis', ['x']);

            try {
                $client->token('orbis', ['x']);
                $this->fail('expected an exception');
            } catch (S2SException $e) {
                $this->assertStringContainsString("HTTP {$status}, {$error}", $e->getMessage());
                $this->assertStringContainsString($hint, $e->getMessage());
            }
        }
    }
}
