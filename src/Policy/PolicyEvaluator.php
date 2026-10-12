<?php

namespace EasySuite\Common\Policy;

use Symfony\Component\HttpFoundation\IpUtils;

/**
 * Evaluates the tenant's conditional-access policies (defined in Security, see docs/architecture/04-policy-sync.md).
 * A pure function of (context, policies, named locations): no database, no network, easy to test.
 *
 * Semantics (like Entra):
 *  - a policy *applies* when its assignments and all its conditions match
 *  - `block` always wins; otherwise the controls of all applying policies are combined (the strictest result)
 *  - `report_only` policies are evaluated but never enforced; they only show up in `Decision::$reportOnly`
 *  - an unknown country (GeoIP miss) never matches a country condition (fails open, as before); an
 *    unknown *control* in a policy is never satisfied (fails closed)
 */
class PolicyEvaluator
{
    /** Controls the user can still satisfy during sign-in by stepping up. */
    private const ACTIONABLE = ['mfa', 'phishing_resistant_mfa'];

    /**
     * @param  array<int, array<string, mixed>>  $policies
     * @param  array<int, array<string, mixed>>  $namedLocations
     */
    public function evaluate(PolicyContext $context, array $policies, array $namedLocations = []): Decision
    {
        usort($policies, fn ($a, $b) => ($a['priority'] ?? 100) <=> ($b['priority'] ?? 100));

        $blocked = false;
        $blockReason = null;
        $blockDetails = [];
        $stepUp = [];
        $applied = [];
        $reportOnly = [];
        $maxAge = null;

        foreach ($policies as $policy) {
            $state = $policy['state'] ?? 'disabled';

            if (! in_array($state, ['enabled', 'report_only'], true)
                || ! $this->assigned($policy, $context)
                || ! $this->conditionsMatch($policy, $context, $namedLocations)) {
                continue;
            }

            $result = $this->grant($policy, $context, $namedLocations);

            if ($state === 'report_only') {
                $reportOnly[] = [
                    'id' => (string) ($policy['id'] ?? ''),
                    'name' => (string) ($policy['name'] ?? ''),
                    'outcome' => $result['block'] ? 'would_block' : ($result['stepUp'] ? 'would_require:'.implode(',', $result['stepUp']) : 'would_allow'),
                ];

                continue;
            }

            $applied[] = ['id' => (string) ($policy['id'] ?? ''), 'name' => (string) ($policy['name'] ?? '')];
            $stepUp = array_merge($stepUp, $result['stepUp']);

            if ($result['block'] && ! $blocked) {
                $blocked = true;
                $blockReason = $this->blockReason($policy);
                $blockDetails = $blockReason === Decision::BLOCK_COUNTRY ? ['country_code' => $context->country] : [];
            }

            if (isset($policy['session']['max_age_minutes']) && is_int($policy['session']['max_age_minutes'])) {
                $maxAge = $maxAge === null ? $policy['session']['max_age_minutes'] : min($maxAge, $policy['session']['max_age_minutes']);
            }
        }

        return new Decision(
            blocked: $blocked,
            blockReason: $blockReason,
            stepUp: array_values(array_unique($stepUp)),
            applied: $applied,
            reportOnly: $reportOnly,
            blockDetails: $blockDetails,
            maxAgeMinutes: $maxAge,
        );
    }

    // ── assignments ───────────────────────────────────────────────────────

    private function assigned(array $policy, PolicyContext $context): bool
    {
        return $this->included($policy['assignments']['clients'] ?? [], $context->clientId)
            && $this->included($policy['assignments']['users'] ?? [], $context->userId);
    }

    /** @param array{include?: string[], exclude?: string[]} $assignment */
    private function included(array $assignment, ?string $id): bool
    {
        $include = $assignment['include'] ?? ['all'];
        $exclude = $assignment['exclude'] ?? [];

        if ($id !== null && in_array($id, $exclude, true)) {
            return false;
        }

        return in_array('all', $include, true) || ($id !== null && in_array($id, $include, true));
    }

    // ── conditions ────────────────────────────────────────────────────────

    private function conditionsMatch(array $policy, PolicyContext $context, array $locations): bool
    {
        $c = $policy['conditions'] ?? [];

        if (isset($c['locations']) && ! $this->locationMatches($c['locations'], $context->ip, $locations)) {
            return false;
        }

        if (isset($c['countries']['codes']) && ! $this->countryMatches($c['countries'], $context->country)) {
            return false;
        }

        if (isset($c['user_risk']) && ! in_array($context->userRisk, (array) $c['user_risk'], true)) {
            return false;
        }

        if (isset($c['client_types']) && ! in_array($context->clientType, (array) $c['client_types'], true)) {
            return false;
        }

        // Device compliance is not known yet: an unknown device counts as not compliant.
        if (isset($c['device']) && array_key_exists('compliant', $c['device']) && $c['device']['compliant'] === true) {
            return false;
        }

        return true;
    }

    /** @param array{include?: string[], exclude?: string[]} $condition */
    private function locationMatches(array $condition, string $ip, array $locations): bool
    {
        $include = $condition['include'] ?? ['any'];
        $exclude = $condition['exclude'] ?? [];

        $inSet = function (array $ids) use ($ip, $locations): bool {
            foreach ($ids as $id) {
                if ($id === 'any' || ($id === 'trusted' && $this->inTrustedLocation($ip, $locations)) || $this->inLocation($ip, $id, $locations)) {
                    return true;
                }
            }

            return false;
        };

        return $inSet($include) && ! $inSet($exclude);
    }

    /** `deny`: applies in these countries. `allow`: applies everywhere else. Unknown country: no match. */
    private function countryMatches(array $condition, ?string $country): bool
    {
        if ($country === null) {
            return false;
        }

        $in = in_array(strtoupper($country), array_map('strtoupper', (array) $condition['codes']), true);

        return ($condition['mode'] ?? 'deny') === 'allow' ? ! $in : $in;
    }

    private function inLocation(string $ip, string $id, array $locations): bool
    {
        foreach ($locations as $location) {
            if (($location['id'] ?? null) === $id && $this->inRanges($ip, (array) ($location['ranges'] ?? []))) {
                return true;
            }
        }

        return false;
    }

    private function inTrustedLocation(string $ip, array $locations): bool
    {
        foreach ($locations as $location) {
            if (($location['trusted'] ?? false) === true && $this->inRanges($ip, (array) ($location['ranges'] ?? []))) {
                return true;
            }
        }

        return false;
    }

    /** IPv4 and IPv6, single addresses and CIDR ranges. */
    private function inRanges(string $ip, array $ranges): bool
    {
        return $ranges !== [] && IpUtils::checkIp($ip, array_map('strval', $ranges));
    }

    // ── grant controls ────────────────────────────────────────────────────

    /** @return array{block: bool, stepUp: string[]} */
    private function grant(array $policy, PolicyContext $context, array $locations): array
    {
        $controls = array_values((array) ($policy['grant']['controls'] ?? []));

        if (in_array('block', $controls, true)) {
            return ['block' => true, 'stepUp' => []];
        }

        if ($controls === []) {
            return ['block' => false, 'stepUp' => []];
        }

        $satisfied = [];
        foreach ($controls as $control) {
            $satisfied[$control] = match ($control) {
                'mfa' => $context->hasMfa(),
                'phishing_resistant_mfa' => $context->hasPhishingResistantMfa(),
                'trusted_network' => $this->inTrustedLocation($context->ip, $locations),
                default => false, // compliant_device (no device signal yet) and anything unknown
            };
        }

        $or = strtoupper($policy['grant']['operator'] ?? 'AND') === 'OR';

        if ($or ? in_array(true, $satisfied, true) : ! in_array(false, $satisfied, true)) {
            return ['block' => false, 'stepUp' => []];
        }

        $missing = array_keys(array_filter($satisfied, fn ($ok) => ! $ok));
        $actionable = array_values(array_intersect($missing, self::ACTIONABLE));

        if ($or) {
            // Any one control is enough: the user can step up if at least one control is something they can do.
            $possible = array_values(array_intersect($controls, self::ACTIONABLE));

            return $possible === [] ? ['block' => true, 'stepUp' => []] : ['block' => false, 'stepUp' => [$possible[0]]];
        }

        // AND: a missing control that cannot be fixed by stepping up (network, device) means no access.
        if (count($actionable) < count($missing)) {
            return ['block' => true, 'stepUp' => []];
        }

        return ['block' => false, 'stepUp' => $actionable];
    }

    private function blockReason(array $policy): string
    {
        $c = $policy['conditions'] ?? [];

        return match (true) {
            isset($c['locations']) => Decision::BLOCK_NETWORK,
            isset($c['countries']) => Decision::BLOCK_COUNTRY,
            isset($c['user_risk']) => Decision::BLOCK_RISK,
            default => Decision::BLOCK_POLICY,
        };
    }
}
