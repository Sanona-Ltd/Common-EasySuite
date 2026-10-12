<?php

namespace EasySuite\Common\Events;

/** Subject-Identifier nach OpenID SSF (Subject Identifiers for Security Event Tokens). */
final class Subject
{
    public static function user(string $sub): array
    {
        return ['format' => 'iss_sub', 'iss' => rtrim((string) config('easysuite.issuer'), '/'), 'sub' => $sub];
    }

    public static function tenant(string $tid): array
    {
        return ['format' => 'opaque', 'type' => 'tenant', 'id' => $tid];
    }

    public static function opaque(string $type, string $id): array
    {
        return ['format' => 'opaque', 'type' => $type, 'id' => $id];
    }
}
