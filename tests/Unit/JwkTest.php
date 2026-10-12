<?php

namespace EasySuite\Common\Tests\Unit;

use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\Jwk;
use EasySuite\Common\Testing\Rsa;
use PHPUnit\Framework\TestCase;

class JwkTest extends TestCase
{
    public function test_jwk_to_pem_round_trips_to_the_same_key(): void
    {
        $publicPem = Rsa::generate()['public'];

        $jwk = Jwk::fromPublicPem($publicPem);

        $this->assertSame('RS256', $jwk['alg']);
        $this->assertSame(Jwk::thumbprint($jwk), $jwk['kid']);
        $this->assertSame($publicPem, Jwk::toPem($jwk));
    }

    public function test_thumbprint_is_stable_and_ignores_extra_members(): void
    {
        $jwk = ['kty' => 'RSA', 'n' => 'abc', 'e' => 'AQAB'];

        $this->assertSame(Jwk::thumbprint($jwk), Jwk::thumbprint($jwk + ['kid' => 'x', 'use' => 'sig']));
    }

    public function test_non_rsa_keys_are_rejected(): void
    {
        $this->expectException(InvalidTokenException::class);

        Jwk::toPem(['kty' => 'EC', 'crv' => 'P-256', 'x' => 'a', 'y' => 'b']);
    }
}
