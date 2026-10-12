<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Oidc\RevokedSessions;
use EasySuite\Common\Tests\TestCase;

class BackChannelLogoutTest extends TestCase
{
    private function logout(string $token)
    {
        return $this->post('/auth/backchannel-logout', ['logout_token' => $token]);
    }

    public function test_valid_logout_token_revokes_the_session(): void
    {
        $this->logout($this->auth->logoutToken(['sid' => 'sid-42']))->assertOk()->assertHeader('Cache-Control', 'no-store, private');

        $this->assertTrue(app(RevokedSessions::class)->isSessionRevoked('sid-42'));
    }

    public function test_logout_token_without_sid_revokes_the_subject(): void
    {
        $this->logout($this->auth->logoutToken(['sid' => null, 'sub' => 'user-5']))->assertOk();

        $this->assertTrue(app(RevokedSessions::class)->isSubjectRevoked('user-5', time()));
    }

    public function test_replayed_logout_token_is_accepted_but_harmless(): void
    {
        $token = $this->auth->logoutToken(['sid' => 'sid-1']);

        $this->logout($token)->assertOk();
        $this->logout($token)->assertOk();
    }

    public function test_missing_token_is_rejected(): void
    {
        $this->post('/auth/backchannel-logout', [])->assertStatus(400);
    }

    public function test_token_without_the_logout_event_is_rejected(): void
    {
        $this->logout($this->auth->logoutToken(['events' => ['https://other/event' => new \stdClass]]))->assertStatus(400);
        $this->assertFalse(app(RevokedSessions::class)->isSessionRevoked('session-1'));
    }

    public function test_token_with_a_nonce_is_rejected(): void
    {
        $this->logout($this->auth->logoutToken(['nonce' => 'x']))->assertStatus(400);
    }

    public function test_token_with_wrong_audience_or_issuer_is_rejected(): void
    {
        $this->logout($this->auth->logoutToken(['aud' => 'other-app']))->assertStatus(400);
        $this->logout($this->auth->logoutToken(['iss' => 'https://evil.test']))->assertStatus(400);
        $this->assertFalse(app(RevokedSessions::class)->isSessionRevoked('session-1'));
    }

    public function test_an_access_token_is_not_a_valid_logout_token(): void
    {
        $this->logout($this->auth->accessToken())->assertStatus(400);
    }
}
