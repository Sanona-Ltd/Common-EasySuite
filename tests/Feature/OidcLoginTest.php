<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Oidc\LoginController;
use EasySuite\Common\Oidc\RevokedSessions;
use EasySuite\Common\Tests\TestCase;
use EasySuite\Common\Tests\TestUser;
use Illuminate\Routing\Router;

class OidcLoginTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        /** @var Router $router */
        $router->middleware(['web', 'auth', 'easysuite.session'])->get('/home', fn () => 'home');
        $router->middleware(['web', 'easysuite.saas-admin'])->get('/saas', fn () => 'saas');
    }

    private function flow(): array
    {
        return [LoginController::SESSION_FLOW => ['state' => 'abc', 'nonce' => 'n', 'verifier' => 'v']];
    }

    public function test_redirect_sends_the_browser_to_auth_with_pkce_and_state(): void
    {
        $response = $this->get('/auth/redirect?acr_values=mfa&max_age=900');

        $response->assertRedirect();
        $location = $response->headers->get('Location');
        parse_str(parse_url($location, PHP_URL_QUERY), $query);

        $this->assertStringStartsWith('https://auth.test/oauth/authorize?', $location);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame('test-client', $query['client_id']);
        $this->assertSame('S256', $query['code_challenge_method']);
        $this->assertSame('mfa', $query['acr_values']);
        $this->assertSame('900', $query['max_age']);
        $this->assertSame('https://app.test/auth/callback', $query['redirect_uri']);
        $this->assertSame($query['state'], session(LoginController::SESSION_FLOW)['state']);

        // Der Challenge ist der SHA-256 des in der Session gehaltenen Verifiers.
        $verifier = session(LoginController::SESSION_FLOW)['verifier'];
        $this->assertSame(
            rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
            $query['code_challenge']
        );
    }

    public function test_login_alias_route_redirects_into_the_flow(): void
    {
        $this->get('/login')->assertRedirect('/auth/redirect');
    }

    public function test_callback_creates_the_user_stub_and_logs_in(): void
    {
        $this->auth->loginAs(
            ['sub' => 'user-9', 'sid' => 'sid-9', 'tid' => 'tenant-9', 'saas_admin' => true, 'amr' => ['pwd', 'mfa']],
            ['name' => 'Nina Beispiel', 'email' => 'nina@example.test']
        );

        $this->withSession($this->flow())
            ->get('/auth/callback?state=abc&code=the-code')
            ->assertRedirect('/');

        $this->assertAuthenticated();
        $user = TestUser::firstWhere('uuid', 'user-9');
        $this->assertSame('Nina Beispiel', $user->name);
        $this->assertSame('tenant-9', $user->tenant_id);
        $this->assertSame('sid-9', session(LoginController::SESSION_SID));
        $this->assertTrue(session(LoginController::SESSION_SAAS_ADMIN));
        $this->assertTrue(session(LoginController::SESSION_MFA));

        // Zweiter Login aktualisiert statt zu duplizieren.
        $this->auth->loginAs(['sub' => 'user-9'], ['name' => 'Nina Neu']);
        $this->withSession($this->flow())->get('/auth/callback?state=abc&code=x');
        $this->assertSame(1, TestUser::count());
        $this->assertSame('Nina Neu', TestUser::first()->name);
    }

    public function test_callback_rejects_a_wrong_state(): void
    {
        $this->withSession($this->flow())
            ->get('/auth/callback?state=forged&code=x')
            ->assertStatus(400);

        $this->assertGuest();
    }

    public function test_callback_without_a_started_flow_is_rejected(): void
    {
        $this->get('/auth/callback?state=abc&code=x')->assertStatus(400);
        $this->assertGuest();
    }

    public function test_callback_rejects_an_error_from_the_server(): void
    {
        $this->withSession($this->flow())
            ->get('/auth/callback?state=abc&error=access_denied&error_description=No')
            ->assertStatus(403);
    }

    public function test_callback_rejects_a_token_for_another_audience(): void
    {
        $this->auth->loginAs(['aud' => 'another-app']);

        $this->withSession($this->flow())->get('/auth/callback?state=abc&code=x')->assertStatus(403);
        $this->assertGuest();
    }

    public function test_logout_ends_the_local_and_the_remote_session(): void
    {
        $this->actingAs(TestUser::create(['uuid' => 'u', 'name' => 'x']))
            ->post('/auth/logout')
            ->assertRedirectContains('https://auth.test/oidc/logout?');

        $this->assertGuest();
    }

    public function test_revoked_session_is_logged_out_on_the_next_request(): void
    {
        $user = TestUser::create(['uuid' => 'u', 'name' => 'x']);
        $session = [LoginController::SESSION_SID => 'sid-1', LoginController::SESSION_SUB => 'u', LoginController::SESSION_LOGIN_AT => time()];

        $this->actingAs($user)->withSession($session)->get('/home')->assertOk();

        app(RevokedSessions::class)->revokeSession('sid-1');

        $this->actingAs($user)->withSession($session)->get('/home')->assertRedirect('/auth/redirect');
    }

    public function test_saas_panel_requires_admin_and_mfa_in_the_session(): void
    {
        $this->get('/saas')->assertForbidden();
        $this->withSession([LoginController::SESSION_SAAS_ADMIN => true])->get('/saas')->assertForbidden();
        $this->withSession([LoginController::SESSION_SAAS_ADMIN => true, LoginController::SESSION_MFA => true])->get('/saas')->assertOk();
    }
}
