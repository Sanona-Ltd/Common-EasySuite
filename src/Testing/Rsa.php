<?php

namespace EasySuite\Common\Testing;

use RuntimeException;

/** Erzeugt RSA-Schlüsselpaare für Tests (und für `easysuite:keys`-Werkzeuge). */
final class Rsa
{
    /** @return array{private: string, public: string} PEM */
    public static function generate(int $bits = 2048): array
    {
        $options = ['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA] + self::config();

        $key = openssl_pkey_new($options);

        if ($key === false || ! openssl_pkey_export($key, $private, null, $options)) {
            throw new RuntimeException('Could not generate an RSA key: '.openssl_error_string());
        }

        return ['private' => $private, 'public' => openssl_pkey_get_details($key)['key']];
    }

    /** PHP unter Windows findet die OpenSSL-Konfiguration nicht von selbst. */
    private static function config(): array
    {
        if (PHP_OS_FAMILY !== 'Windows' || getenv('OPENSSL_CONF')) {
            return [];
        }

        $config = dirname(PHP_BINARY).'/extras/ssl/openssl.cnf';

        return is_file($config) ? ['config' => $config] : [];
    }
}
