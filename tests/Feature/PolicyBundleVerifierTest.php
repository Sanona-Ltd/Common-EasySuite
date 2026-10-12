<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Policy\BundleVerifier;
use EasySuite\Common\Testing\FakeAuthServer;
use EasySuite\Common\Tests\TestCase;

class PolicyBundleVerifierTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // In this test the fake server plays Security.
        config(['easysuite.services.security.url' => 'https://auth.test']);
    }

    private function bundle(array $claims = [], ?FakeAuthServer $signer = null): string
    {
        return ($signer ?? $this->auth)->sign($claims + [
            'iss' => 'https://auth.test',
            'aud' => 'https://app.test',
            'iat' => time(),
            'tid' => 'tenant-1',
            'version' => 7,
            'policies' => [['id' => 'p1', 'name' => 'MFA for all', 'state' => 'enabled']],
            'named_locations' => [['id' => 'hq', 'trusted' => true, 'ranges' => ['10.0.0.0/8']]],
        ]);
    }

    public function test_a_valid_bundle_is_returned_normalised(): void
    {
        $bundle = app(BundleVerifier::class)->verify($this->bundle(), 'tenant-1');

        $this->assertSame(7, $bundle['version']);
        $this->assertSame('tenant-1', $bundle['tid']);
        $this->assertSame('p1', $bundle['policies'][0]['id']);
        $this->assertSame('hq', $bundle['named_locations'][0]['id']);
    }

    private function assertRejected(string $jws, string $tenant = 'tenant-1'): void
    {
        try {
            app(BundleVerifier::class)->verify($jws, $tenant);
        } catch (InvalidTokenException) {
            $this->addToAssertionCount(1);

            return;
        }

        $this->fail('Bundle was accepted but must be rejected.');
    }

    public function test_a_bundle_for_another_tenant_is_rejected(): void
    {
        $this->assertRejected($this->bundle(['tid' => 'tenant-2']));
        $this->assertRejected($this->bundle(), 'tenant-2');
    }

    public function test_a_bundle_signed_by_somebody_else_is_rejected(): void
    {
        $attacker = new FakeAuthServer('https://auth.test', 'x');

        $this->assertRejected($this->bundle([], $attacker));
        $this->assertRejected($this->bundle([], $attacker), 'tenant-1');
    }

    public function test_wrong_issuer_or_audience_is_rejected(): void
    {
        $this->assertRejected($this->bundle(['iss' => 'https://evil.test']));
        $this->assertRejected($this->bundle(['aud' => 'https://other.test']));
    }

    public function test_malformed_content_is_rejected(): void
    {
        $this->assertRejected($this->bundle(['version' => 'seven']));
        $this->assertRejected($this->bundle(['version' => 0]));
        $this->assertRejected($this->bundle(['policies' => 'all']));
        $this->assertRejected($this->bundle(['iat' => null]));
        $this->assertRejected('not-a-jwt');
    }

    public function test_a_tampered_payload_is_rejected(): void
    {
        [$h, , $s] = explode('.', $this->bundle());
        $forged = rtrim(strtr(base64_encode(json_encode([
            'iss' => 'https://auth.test', 'aud' => 'https://app.test', 'iat' => time(), 'tid' => 'tenant-1', 'version' => 99, 'policies' => [],
        ])), '+/', '-_'), '=');

        $this->assertRejected("{$h}.{$forged}.{$s}");
    }
}
