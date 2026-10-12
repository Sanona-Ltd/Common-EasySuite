<?php

namespace EasySuite\Common\Policy;

/** Everything a policy may look at when a user signs in. */
final class PolicyContext
{
    /**
     * @param  string[]  $amr  authentication methods used so far (`pwd`, `otp`, `hwk`, `mfa`)
     * @param  string|null  $clientId  OAuth client the user is signing in to, when known (null for a direct login at Auth)
     * @param  string  $userRisk  `none|low|medium|high` (from Security, `none` when unknown)
     */
    public function __construct(
        public readonly string $tenantId,
        public readonly string $userId,
        public readonly string $ip,
        public readonly ?string $country = null,
        public readonly array $amr = ['pwd'],
        public readonly ?string $clientId = null,
        public readonly string $clientType = 'browser',
        public readonly string $userRisk = 'none',
    ) {}

    public function hasMfa(): bool
    {
        return in_array('mfa', $this->amr, true);
    }

    public function hasPhishingResistantMfa(): bool
    {
        return $this->hasMfa() && in_array('hwk', $this->amr, true);
    }
}
