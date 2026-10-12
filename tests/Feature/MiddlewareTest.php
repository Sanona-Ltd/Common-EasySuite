<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Oidc\RevokedSessions;
use EasySuite\Common\Support\TenantContext;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;

class MiddlewareTest extends TestCase
{
    protected function defineRoutes($router): void
    {
        /** @var Router $router */
        $echo = fn (Request $r) => response()->json([
            'sub' => $r->attributes->get('easysuite.token')->sub(),
            'tenant' => app(TenantContext::class)->id(),
        ]);

        $router->get('/t', $echo)->middleware('easysuite.token');
        $router->get('/scoped', $echo)->middleware(['easysuite.token', 'easysuite.scope:orbis:users.read,orbis:mail.read']);
        $router->get('/user-only', $echo)->middleware(['easysuite.token', 'easysuite.type:user']);
        $router->get('/app-only', $echo)->middleware(['easysuite.token', 'easysuite.type:app']);
        $router->get('/admin', $echo)->middleware(['easysuite.token', 'easysuite.saas-admin']);
    }

    public function test_missing_token_is_401_problem_json(): void
    {
        $this->getJson('/t')
            ->assertUnauthorized()
            ->assertHeader('WWW-Authenticate')
            ->assertHeader('Content-Type', 'application/problem+json');
    }

    public function test_invalid_token_is_401(): void
    {
        $this->withToken('garbage')->getJson('/t')->assertUnauthorized();
    }

    public function test_valid_token_passes_and_sets_tenant_context(): void
    {
        $this->withToken($this->auth->accessToken(['tid' => 'tenant-7']))
            ->getJson('/t')
            ->assertOk()
            ->assertJson(['sub' => 'user-1', 'tenant' => 'tenant-7']);
    }

    public function test_scope_middleware_requires_all_scopes(): void
    {
        $this->withToken($this->auth->accessToken(['scopes' => ['orbis:users.read']]))
            ->getJson('/scoped')->assertForbidden();

        $this->withToken($this->auth->accessToken(['scopes' => ['orbis:users.read', 'orbis:mail.read']]))
            ->getJson('/scoped')->assertOk();
    }

    public function test_user_and_app_tokens_are_kept_apart(): void
    {
        $user = $this->auth->accessToken();
        $app = $this->auth->appToken();

        $this->withToken($user)->getJson('/user-only')->assertOk();
        $this->withToken($app)->getJson('/user-only')->assertForbidden();
        $this->withToken($app)->getJson('/app-only')->assertOk();
        $this->withToken($user)->getJson('/app-only')->assertForbidden();
    }

    public function test_saas_admin_needs_claim_and_mfa(): void
    {
        $this->withToken($this->auth->accessToken())->getJson('/admin')->assertForbidden();
        $this->withToken($this->auth->accessToken(['saas_admin' => true]))->getJson('/admin')->assertForbidden();
        $this->withToken($this->auth->accessToken(['saas_admin' => true, 'amr' => ['pwd', 'mfa']]))->getJson('/admin')->assertOk();
    }

    public function test_revoked_session_is_rejected(): void
    {
        app(RevokedSessions::class)->revokeSession('session-1');

        $this->withToken($this->auth->accessToken(['sid' => 'session-1']))->getJson('/t')->assertUnauthorized();
        $this->withToken($this->auth->accessToken(['sid' => 'other']))->getJson('/t')->assertOk();
    }

    public function test_disabled_subject_is_rejected(): void
    {
        app(RevokedSessions::class)->revokeSubject('user-1');

        $this->withToken($this->auth->accessToken())->getJson('/t')->assertUnauthorized();
        $this->withToken($this->auth->accessToken(['sub' => 'user-2']))->getJson('/t')->assertOk();
    }
}
