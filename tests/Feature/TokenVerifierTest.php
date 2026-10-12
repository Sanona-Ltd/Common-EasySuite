<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\Jwk;
use EasySuite\Common\Jwt\JwksProvider;
use EasySuite\Common\Jwt\TokenVerifier;
use EasySuite\Common\Jwt\VerifiedToken;
use EasySuite\Common\Testing\FakeAuthServer;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Support\Facades\Http;

class TokenVerifierTest extends TestCase
{
    private function verify(string $jwt, ?string $audience = 'test-client', bool $requireExp = true): VerifiedToken
    {
        return app(TokenVerifier::class)->verify(
            $jwt,
            'https://auth.test',
            'https://auth.test/.well-known/jwks.json',
            $audience,
            30,
            $requireExp,
        );
    }

    private function assertRejected(string $jwt, ?string $audience = 'test-client'): void
    {
        try {
            $this->verify($jwt, $audience);
        } catch (InvalidTokenException) {
            $this->addToAssertionCount(1);

            return;
        }

        $this->fail('Token was accepted but must be rejected.');
    }

    public function test_valid_token_is_accepted_and_exposes_claims(): void
    {
        $token = $this->verify($this->auth->accessToken([
            'tid' => 'tenant-9', 'sid' => 'sid-9', 'scopes' => ['a', 'b'], 'saas_admin' => true, 'amr' => ['pwd', 'mfa'],
        ]));

        $this->assertSame('user-1', $token->sub());
        $this->assertSame('tenant-9', $token->tid());
        $this->assertSame('sid-9', $token->sid());
        $this->assertTrue($token->hasScope('b'));
        $this->assertTrue($token->isUser());
        $this->assertTrue($token->isSaasAdmin());
        $this->assertTrue($token->hasMfa());
        $this->assertIsInt($token->expiresAt());
    }

    public function test_scope_string_and_scopes_array_are_both_understood(): void
    {
        $token = $this->verify($this->auth->accessToken(['scopes' => ['a'], 'scope' => 'b c']));

        $this->assertEqualsCanonicalizing(['a', 'b', 'c'], $token->scopes());
    }

    public function test_token_type_falls_back_to_sub_equals_azp(): void
    {
        $app = $this->verify($this->auth->accessToken(['idtyp' => null, 'sub' => 'c1', 'azp' => 'c1']));
        $user = $this->verify($this->auth->accessToken(['idtyp' => null, 'sub' => 'u1', 'azp' => 'c1']));

        $this->assertTrue($app->isApp());
        $this->assertTrue($user->isUser());
    }

    public function test_expired_token_is_rejected(): void
    {
        $this->assertRejected($this->auth->accessToken(['iat' => time() - 4000, 'nbf' => time() - 4000, 'exp' => time() - 3600]));
    }

    public function test_token_without_expiry_is_rejected(): void
    {
        $this->assertRejected($this->auth->accessToken(['exp' => null]));
    }

    public function test_token_from_the_future_is_rejected(): void
    {
        $this->assertRejected($this->auth->accessToken(['nbf' => time() + 3600, 'iat' => time() + 3600, 'exp' => time() + 7200]));
    }

    public function test_wrong_audience_is_rejected(): void
    {
        $this->assertRejected($this->auth->accessToken(['aud' => 'someone-else']));
    }

    public function test_wrong_issuer_is_rejected(): void
    {
        $this->assertRejected($this->auth->accessToken(['iss' => 'https://evil.test']));
    }

    public function test_token_signed_by_a_foreign_key_is_rejected(): void
    {
        $attacker = new FakeAuthServer('https://auth.test', 'test-client');

        // Gleicher kid wie der echte Server, aber anderer Schlüssel.
        $this->assertRejected($attacker->accessToken([], ['kid' => $this->auth->kid]));
    }

    public function test_unknown_kid_is_rejected(): void
    {
        $this->assertRejected($this->auth->accessToken([], ['kid' => 'does-not-exist']));
    }

    public function test_tampered_payload_is_rejected(): void
    {
        [$header, , $signature] = explode('.', $this->auth->accessToken());
        $forged = Jwk::b64urlEncode(json_encode([
            'iss' => 'https://auth.test', 'sub' => 'admin', 'aud' => 'test-client', 'exp' => time() + 900,
        ]));

        $this->assertRejected("{$header}.{$forged}.{$signature}");
    }

    public function test_alg_none_is_rejected(): void
    {
        $header = Jwk::b64urlEncode(json_encode(['alg' => 'none', 'typ' => 'JWT']));
        $payload = Jwk::b64urlEncode(json_encode([
            'iss' => 'https://auth.test', 'sub' => 'admin', 'aud' => 'test-client', 'exp' => time() + 900,
        ]));

        $this->assertRejected("{$header}.{$payload}.");
    }

    public function test_hs256_confusion_attack_is_rejected(): void
    {
        $header = Jwk::b64urlEncode(json_encode(['alg' => 'HS256', 'typ' => 'JWT', 'kid' => $this->auth->kid]));
        $payload = Jwk::b64urlEncode(json_encode([
            'iss' => 'https://auth.test', 'sub' => 'admin', 'aud' => 'test-client', 'exp' => time() + 900,
        ]));
        $pem = Jwk::toPem($this->auth->jwks()['keys'][0]);
        $signature = Jwk::b64urlEncode(hash_hmac('sha256', "{$header}.{$payload}", $pem, true));

        $this->assertRejected("{$header}.{$payload}.{$signature}");
    }

    public function test_garbage_is_rejected(): void
    {
        $this->assertRejected('not-a-jwt');
    }

    public function test_rotated_key_is_picked_up_after_a_cache_miss(): void
    {
        // Verifier lädt das JWKS und cacht es.
        $this->verify($this->auth->accessToken());

        // Auth rotiert: neuer Schlüssel (anderer kid) wird veröffentlicht.
        $rotated = new FakeAuthServer('https://auth.test', 'test-client');
        $this->auth->publishKeyOf($rotated);

        $this->assertSame('user-1', $this->verify($rotated->accessToken())->sub());
    }

    public function test_a_local_key_source_is_used_without_any_http_request(): void
    {
        Http::fake(); // would return 200 with an empty body for anything
        $jwks = $this->auth->jwks()['keys'][0];
        app(JwksProvider::class)->useLocalSource(
            'https://auth.test/.well-known/jwks.json',
            fn () => [$jwks['kid'] => Jwk::toPem($jwks)]
        );

        $this->assertSame('user-1', $this->verify($this->auth->accessToken())->sub());
        Http::assertNothingSent();

        // An unknown kid is rejected without trying to refetch.
        $this->assertRejected($this->auth->accessToken([], ['kid' => 'other']));
        Http::assertNothingSent();
    }
}
