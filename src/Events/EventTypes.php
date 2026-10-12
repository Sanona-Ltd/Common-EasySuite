<?php

namespace EasySuite\Common\Events;

/**
 * Event-Typen. Im Code und in der Konfiguration dürfen Kurznamen (`session.revoked`) verwendet werden,
 * auf dem Draht stehen immer URIs.
 *
 * Standard-Events (OpenID Shared Signals) behalten ihre offizielle URI, alle anderen liegen unter
 * https://schemas.easysuite.ch/event/<resource>/<action>.
 */
final class EventTypes
{
    public const SESSION_REVOKED = 'https://schemas.openid.net/secevent/caep/event-type/session-revoked';

    public const CREDENTIAL_CHANGE = 'https://schemas.openid.net/secevent/caep/event-type/credential-change';

    public const ACCOUNT_DISABLED = 'https://schemas.openid.net/secevent/risc/event-type/account-disabled';

    public const ACCOUNT_ENABLED = 'https://schemas.openid.net/secevent/risc/event-type/account-enabled';

    private const STANDARD = [
        'session.revoked' => self::SESSION_REVOKED,
        'credential.changed' => self::CREDENTIAL_CHANGE,
        'user.disabled' => self::ACCOUNT_DISABLED,
        'user.enabled' => self::ACCOUNT_ENABLED,
    ];

    private const BASE = 'https://schemas.easysuite.ch/event/';

    public static function resolve(string $type): string
    {
        if (str_contains($type, '://')) {
            return $type;
        }

        return self::STANDARD[$type] ?? self::BASE.str_replace('.', '/', $type);
    }

    /** Umkehrung für Anzeige/Logs. */
    public static function shortName(string $uri): string
    {
        $standard = array_search($uri, self::STANDARD, true);

        if ($standard !== false) {
            return $standard;
        }

        return str_starts_with($uri, self::BASE) ? str_replace('/', '.', substr($uri, strlen(self::BASE))) : $uri;
    }
}
