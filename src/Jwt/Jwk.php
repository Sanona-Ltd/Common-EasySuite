<?php

namespace EasySuite\Common\Jwt;

/**
 * Minimale RSA-JWK-Hilfen (RFC 7517/7638): JWK ⇄ PEM und Thumbprint.
 */
final class Jwk
{
    public static function toPem(array $jwk): string
    {
        if (($jwk['kty'] ?? null) !== 'RSA' || ! isset($jwk['n'], $jwk['e'])) {
            throw new InvalidTokenException('Unsupported JWK: only RSA keys are accepted.');
        }

        $rsaPublicKey = self::sequence(
            self::integer(self::b64urlDecode($jwk['n'])).self::integer(self::b64urlDecode($jwk['e']))
        );
        // AlgorithmIdentifier { rsaEncryption, NULL }
        $algorithm = self::sequence("\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01\x05\x00");
        $bitString = "\x03".self::length(strlen($rsaPublicKey) + 1)."\x00".$rsaPublicKey;
        $der = self::sequence($algorithm.$bitString);

        return "-----BEGIN PUBLIC KEY-----\n".chunk_split(base64_encode($der), 64, "\n")."-----END PUBLIC KEY-----\n";
    }

    public static function fromPublicPem(string $pem): array
    {
        $resource = openssl_pkey_get_public($pem);
        $details = $resource ? openssl_pkey_get_details($resource) : false;

        if ($details === false || ! isset($details['rsa'])) {
            throw new InvalidTokenException('Not a valid RSA public key.');
        }

        $jwk = [
            'kty' => 'RSA',
            'n' => self::b64urlEncode($details['rsa']['n']),
            'e' => self::b64urlEncode($details['rsa']['e']),
        ];

        return ['kid' => self::thumbprint($jwk), 'use' => 'sig', 'alg' => 'RS256'] + $jwk;
    }

    /** RFC 7638 SHA-256 thumbprint. */
    public static function thumbprint(array $jwk): string
    {
        $canonical = json_encode(
            ['e' => $jwk['e'], 'kty' => $jwk['kty'], 'n' => $jwk['n']],
            JSON_UNESCAPED_SLASHES
        );

        return self::b64urlEncode(hash('sha256', $canonical, true));
    }

    public static function b64urlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    public static function b64urlDecode(string $value): string
    {
        $decoded = base64_decode(strtr($value, '-_', '+/').str_repeat('=', (4 - strlen($value) % 4) % 4), true);

        if ($decoded === false) {
            throw new InvalidTokenException('Invalid base64url value.');
        }

        return $decoded;
    }

    private static function integer(string $value): string
    {
        $value = ltrim($value, "\x00");

        if ($value === '' || ord($value[0]) > 0x7F) {
            $value = "\x00".$value;
        }

        return "\x02".self::length(strlen($value)).$value;
    }

    private static function sequence(string $content): string
    {
        return "\x30".self::length(strlen($content)).$content;
    }

    private static function length(int $length): string
    {
        if ($length < 128) {
            return chr($length);
        }

        $bytes = ltrim(pack('N', $length), "\x00");

        return chr(0x80 | strlen($bytes)).$bytes;
    }
}
