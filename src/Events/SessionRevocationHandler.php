<?php

namespace EasySuite\Common\Events;

use EasySuite\Common\Oidc\RevokedSessions;

/** Eingebauter Handler: `session.revoked` und `user.disabled` füllen die lokale Sperrliste. */
class SessionRevocationHandler
{
    public function __construct(private readonly RevokedSessions $revoked) {}

    public function __invoke(ReceivedEvent $event): void
    {
        if ($event->type === EventTypes::SESSION_REVOKED && $event->get('sid')) {
            $this->revoked->revokeSession($event->get('sid'));

            return;
        }

        if ($sub = $event->subject()['sub'] ?? null) {
            $this->revoked->revokeSubject($sub);
        }
    }
}
