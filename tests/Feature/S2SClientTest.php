<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Jwt\TokenVerifier;
use EasySuite\Common\S2S\Client;
use EasySuite\Common\S2S\S2SException;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;

class S2SClientTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        config(['easysuite.services.orbis' => ['url' => 'https://orbis.test', 'audience' => 'orbis-client']]);
        Http::fake(['https://orbis.test/*' => Http::response(['roles' => ['admin']])]);
    }

    private function tokenRequests(): int
    {
        return Http::recorded(fn (Request $r) => str_ends_with($r->url(), '/oauth/token'))->count();
    }

    public function test_requests_carry_a_client_credentials_token_for_the_target_audience(): void
    {
        $response = app(Client::class)->request('orbis', ['orbis:users.read'])->get('/s2s/users/u1/roles');

        $this->assertSame(['admin'], $response->json('roles'));

        Http::assertSent(function (Request $request) {
            if ($request->url() !== 'https://orbis.test/s2s/users/u1/roles') {
                return false;
            }

            $jwt = str_replace('Bearer ', '', $request->header('Authorization')[0]);
            $token = app(TokenVerifier::class)->verify($jwt, 'https://auth.test', 'https://auth.test/.well-known/jwks.json', 'orbis-client');

            return $token->hasScope('orbis:users.read') && $token->isApp() && $request->hasHeader('X-Request-Id');
        });
    }

    public function test_token_is_cached_between_requests(): void
    {
        $client = app(Client::class);

        $client->request('orbis', ['orbis:users.read'])->get('/a');
        $client->request('orbis', ['orbis:users.read'])->get('/b');

        $this->assertSame(1, $this->tokenRequests());

        // Anderer Scope ⇒ anderes Token.
        $client->request('orbis', ['orbis:mail.read'])->get('/c');
        $this->assertSame(2, $this->tokenRequests());
    }

    public function test_forget_drops_the_cached_token(): void
    {
        $client = app(Client::class);

        $client->request('orbis', ['x'])->get('/a');
        $client->forget('orbis', ['x']);
        $client->request('orbis', ['x'])->get('/a');

        $this->assertSame(2, $this->tokenRequests());
    }

    public function test_unknown_service_or_missing_audience_fails_clearly(): void
    {
        config(['easysuite.services.billing.audience' => null]);

        $this->expectException(S2SException::class);
        app(Client::class)->request('billing');
    }

    public function test_token_endpoint_failure_raises(): void
    {
        $this->auth->failTokenEndpoint(401);

        $this->expectException(S2SException::class);
        app(Client::class)->request('orbis', ['x']);
    }
}
