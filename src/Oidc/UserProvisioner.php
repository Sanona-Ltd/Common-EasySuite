<?php

namespace EasySuite\Common\Oidc;

use EasySuite\Common\Jwt\VerifiedToken;
use Illuminate\Contracts\Auth\Authenticatable;

/**
 * Legt nach erfolgreichem Login den lokalen User-Stub an bzw. aktualisiert ihn.
 * Das System speichert keine Credentials, `sub` ist der Schlüssel.
 */
interface UserProvisioner
{
    /** @param array<string, mixed> $profile sub, email, name … (UserInfo) */
    public function resolve(array $profile, VerifiedToken $token): Authenticatable;
}
