<?php

namespace EasySuite\Common\Policy;

/** Outcome of evaluating the tenant's policies for one sign-in. */
final class Decision
{
    public const BLOCK_NETWORK = 'network';

    public const BLOCK_COUNTRY = 'country';

    public const BLOCK_RISK = 'risk';

    public const BLOCK_POLICY = 'policy';

    /** The tenant is suspended or deleted in Orbis. */
    public const BLOCK_TENANT = 'tenant';

    /**
     * @param  string[]  $stepUp  controls the user can still satisfy: `mfa`, `phishing_resistant_mfa`
     * @param  array<int, array{id: string, name: string}>  $applied  enforced policies that matched
     * @param  array<int, array{id: string, name: string, outcome: string}>  $reportOnly  what report-only policies would have done
     * @param  array<string, mixed>  $blockDetails  e.g. ['country_code' => 'RU'] for the blocked page
     */
    public function __construct(
        public readonly bool $blocked = false,
        public readonly ?string $blockReason = null,
        public readonly array $stepUp = [],
        public readonly array $applied = [],
        public readonly array $reportOnly = [],
        public readonly array $blockDetails = [],
        public readonly ?int $maxAgeMinutes = null,
    ) {}

    public static function allow(): self
    {
        return new self;
    }

    public function requiresMfa(): bool
    {
        return $this->stepUp !== [];
    }

    public function requiresPhishingResistantMfa(): bool
    {
        return in_array('phishing_resistant_mfa', $this->stepUp, true);
    }

    /** Ids of the enforced and report-only policies, for the sign-in event. */
    public function policiesApplied(): array
    {
        return [
            'enforced' => array_column($this->applied, 'id'),
            'report_only' => $this->reportOnly,
        ];
    }
}
