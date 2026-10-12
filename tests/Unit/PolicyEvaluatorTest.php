<?php

namespace Tests\Unit;

use EasySuite\Common\Policy\Decision;
use EasySuite\Common\Policy\PolicyContext;
use EasySuite\Common\Policy\PolicyEvaluator;
use PHPUnit\Framework\TestCase;

class PolicyEvaluatorTest extends TestCase
{
    private const LOCATIONS = [
        ['id' => 'hq', 'name' => 'HQ', 'trusted' => true, 'ranges' => ['203.0.113.0/24', '2001:db8::/32']],
        ['id' => 'vpn', 'name' => 'VPN', 'trusted' => false, 'ranges' => ['198.51.100.7']],
    ];

    private function ctx(array $overrides = []): PolicyContext
    {
        return new PolicyContext(...($overrides + [
            'tenantId' => 't1', 'userId' => 'u1', 'ip' => '192.0.2.10', 'country' => 'CH', 'amr' => ['pwd'],
        ]));
    }

    private function policy(array $overrides = []): array
    {
        return $overrides + ['id' => 'p', 'name' => 'Policy', 'state' => 'enabled', 'priority' => 100, 'grant' => ['controls' => ['mfa']]];
    }

    private function evaluate(PolicyContext $ctx, array ...$policies): Decision
    {
        return (new PolicyEvaluator)->evaluate($ctx, $policies, self::LOCATIONS);
    }

    // ── baseline behaviour ────────────────────────────────────────────────

    public function test_no_policies_allow_everything(): void
    {
        $d = $this->evaluate($this->ctx());

        $this->assertFalse($d->blocked);
        $this->assertSame([], $d->stepUp);
        $this->assertFalse($d->requiresMfa());
    }

    public function test_an_mfa_policy_asks_for_mfa_until_the_user_has_it(): void
    {
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(), $this->policy())->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['amr' => ['pwd', 'otp', 'mfa']]), $this->policy())->stepUp);
    }

    public function test_disabled_policies_are_ignored(): void
    {
        $this->assertSame([], $this->evaluate($this->ctx(), $this->policy(['state' => 'disabled']))->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(), $this->policy(['state' => 'nonsense']))->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(), $this->policy(['state' => null]))->stepUp);
    }

    public function test_report_only_policies_are_never_enforced_but_reported(): void
    {
        $d = $this->evaluate($this->ctx(), $this->policy(['id' => 'ro', 'state' => 'report_only']), $this->policy(['id' => 'rb', 'state' => 'report_only', 'grant' => ['controls' => ['block']]]));

        $this->assertFalse($d->blocked);
        $this->assertSame([], $d->stepUp);
        $this->assertSame([], $d->applied);
        $this->assertSame(
            [['id' => 'ro', 'name' => 'Policy', 'outcome' => 'would_require:mfa'], ['id' => 'rb', 'name' => 'Policy', 'outcome' => 'would_block']],
            $d->reportOnly
        );
    }

    public function test_block_always_wins_over_other_policies(): void
    {
        $d = $this->evaluate(
            $this->ctx(['amr' => ['pwd', 'otp', 'mfa']]),
            $this->policy(['id' => 'a']),
            $this->policy(['id' => 'b', 'grant' => ['controls' => ['block']]]),
        );

        $this->assertTrue($d->blocked);
        $this->assertSame(Decision::BLOCK_POLICY, $d->blockReason);
        $this->assertSame(['a', 'b'], array_column($d->applied, 'id'));
    }

    // ── assignments ───────────────────────────────────────────────────────

    public function test_client_assignment_include_and_exclude(): void
    {
        $forBilling = $this->policy(['assignments' => ['clients' => ['include' => ['billing']]]]);

        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['clientId' => 'billing']), $forBilling)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['clientId' => 'orbis']), $forBilling)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['clientId' => null]), $forBilling)->stepUp, 'a direct login at Auth is not "billing"');

        $allButOrbis = $this->policy(['assignments' => ['clients' => ['include' => ['all'], 'exclude' => ['orbis']]]]);
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['clientId' => 'billing']), $allButOrbis)->stepUp);
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['clientId' => null]), $allButOrbis)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['clientId' => 'orbis']), $allButOrbis)->stepUp);
    }

    public function test_user_assignment_exclusion_wins(): void
    {
        $p = $this->policy(['assignments' => ['users' => ['include' => ['all'], 'exclude' => ['breakglass']]]]);

        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['userId' => 'someone']), $p)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['userId' => 'breakglass']), $p)->stepUp);

        $only = $this->policy(['assignments' => ['users' => ['include' => ['u1']]]]);
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['userId' => 'u1']), $only)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['userId' => 'u2']), $only)->stepUp);
    }

    // ── conditions ────────────────────────────────────────────────────────

    public function test_block_outside_trusted_locations(): void
    {
        $p = $this->policy(['conditions' => ['locations' => ['include' => ['any'], 'exclude' => ['trusted']]], 'grant' => ['controls' => ['block']]]);

        $outside = $this->evaluate($this->ctx(['ip' => '192.0.2.10']), $p);
        $this->assertTrue($outside->blocked);
        $this->assertSame(Decision::BLOCK_NETWORK, $outside->blockReason);

        $this->assertFalse($this->evaluate($this->ctx(['ip' => '203.0.113.77']), $p)->blocked, 'inside HQ IPv4');
        $this->assertFalse($this->evaluate($this->ctx(['ip' => '2001:db8:1::5']), $p)->blocked, 'inside HQ IPv6');
        $this->assertTrue($this->evaluate($this->ctx(['ip' => '2001:db9::1']), $p)->blocked, 'outside HQ IPv6');
        $this->assertTrue($this->evaluate($this->ctx(['ip' => '198.51.100.7']), $p)->blocked, 'VPN is a named location but not trusted');
    }

    public function test_a_specific_named_location_can_be_included_or_excluded(): void
    {
        $p = $this->policy(['conditions' => ['locations' => ['include' => ['vpn']]]]);

        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['ip' => '198.51.100.7']), $p)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['ip' => '192.0.2.10']), $p)->stepUp);
    }

    public function test_country_allow_list_blocks_everywhere_else(): void
    {
        $p = $this->policy(['conditions' => ['countries' => ['mode' => 'allow', 'codes' => ['CH', 'de']]], 'grant' => ['controls' => ['block']]]);

        $this->assertFalse($this->evaluate($this->ctx(['country' => 'CH']), $p)->blocked);
        $this->assertFalse($this->evaluate($this->ctx(['country' => 'DE']), $p)->blocked, 'case insensitive');

        $ru = $this->evaluate($this->ctx(['country' => 'RU']), $p);
        $this->assertTrue($ru->blocked);
        $this->assertSame(Decision::BLOCK_COUNTRY, $ru->blockReason);
        $this->assertSame(['country_code' => 'RU'], $ru->blockDetails);
    }

    public function test_country_deny_list_blocks_only_those(): void
    {
        $p = $this->policy(['conditions' => ['countries' => ['mode' => 'deny', 'codes' => ['KP']]], 'grant' => ['controls' => ['block']]]);

        $this->assertTrue($this->evaluate($this->ctx(['country' => 'KP']), $p)->blocked);
        $this->assertFalse($this->evaluate($this->ctx(['country' => 'CH']), $p)->blocked);
    }

    public function test_an_unknown_country_never_matches_a_country_condition(): void
    {
        $allow = $this->policy(['conditions' => ['countries' => ['mode' => 'allow', 'codes' => ['CH']]], 'grant' => ['controls' => ['block']]]);

        $this->assertFalse($this->evaluate($this->ctx(['country' => null]), $allow)->blocked);
    }

    public function test_user_risk_condition(): void
    {
        $p = $this->policy(['conditions' => ['user_risk' => ['medium', 'high']]]);

        $this->assertSame([], $this->evaluate($this->ctx(['userRisk' => 'none']), $p)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['userRisk' => 'low']), $p)->stepUp);
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['userRisk' => 'high']), $p)->stepUp);

        $block = $this->policy(['conditions' => ['user_risk' => ['high']], 'grant' => ['controls' => ['block']]]);
        $this->assertSame(Decision::BLOCK_RISK, $this->evaluate($this->ctx(['userRisk' => 'high']), $block)->blockReason);
    }

    public function test_client_type_condition(): void
    {
        $p = $this->policy(['conditions' => ['client_types' => ['native']]]);

        $this->assertSame([], $this->evaluate($this->ctx(['clientType' => 'browser']), $p)->stepUp);
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['clientType' => 'native']), $p)->stepUp);
    }

    public function test_all_conditions_must_match(): void
    {
        $p = $this->policy(['conditions' => ['locations' => ['include' => ['any'], 'exclude' => ['trusted']], 'user_risk' => ['high']]]);

        $this->assertSame([], $this->evaluate($this->ctx(['userRisk' => 'high', 'ip' => '203.0.113.5']), $p)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['userRisk' => 'none', 'ip' => '192.0.2.10']), $p)->stepUp);
        $this->assertSame(['mfa'], $this->evaluate($this->ctx(['userRisk' => 'high', 'ip' => '192.0.2.10']), $p)->stepUp);
    }

    // ── grant controls ────────────────────────────────────────────────────

    public function test_phishing_resistant_mfa_needs_a_security_key_not_just_any_second_factor(): void
    {
        $p = $this->policy(['grant' => ['controls' => ['phishing_resistant_mfa']]]);

        $this->assertSame(['phishing_resistant_mfa'], $this->evaluate($this->ctx(['amr' => ['pwd']]), $p)->stepUp);
        $this->assertSame(['phishing_resistant_mfa'], $this->evaluate($this->ctx(['amr' => ['pwd', 'otp', 'mfa']]), $p)->stepUp);
        $this->assertSame([], $this->evaluate($this->ctx(['amr' => ['pwd', 'hwk', 'mfa']]), $p)->stepUp);
        $this->assertTrue($this->evaluate($this->ctx(), $p)->requiresPhishingResistantMfa());
    }

    public function test_trusted_network_control_cannot_be_fixed_by_stepping_up(): void
    {
        $p = $this->policy(['grant' => ['controls' => ['trusted_network']]]);

        $this->assertTrue($this->evaluate($this->ctx(['ip' => '192.0.2.10']), $p)->blocked);
        $this->assertFalse($this->evaluate($this->ctx(['ip' => '203.0.113.5']), $p)->blocked);
    }

    public function test_and_requires_every_control(): void
    {
        $p = $this->policy(['grant' => ['operator' => 'AND', 'controls' => ['mfa', 'trusted_network']]]);

        // MFA done but outside the trusted network: can't be fixed → blocked.
        $this->assertTrue($this->evaluate($this->ctx(['amr' => ['pwd', 'otp', 'mfa'], 'ip' => '192.0.2.10']), $p)->blocked);
        // Inside the network, MFA missing → step up.
        $inside = $this->evaluate($this->ctx(['ip' => '203.0.113.5']), $p);
        $this->assertFalse($inside->blocked);
        $this->assertSame(['mfa'], $inside->stepUp);
        // Both satisfied.
        $both = $this->evaluate($this->ctx(['amr' => ['pwd', 'otp', 'mfa'], 'ip' => '203.0.113.5']), $p);
        $this->assertFalse($both->blocked);
        $this->assertSame([], $both->stepUp);
    }

    public function test_or_needs_only_one_control(): void
    {
        $p = $this->policy(['grant' => ['operator' => 'OR', 'controls' => ['mfa', 'trusted_network']]]);

        $this->assertSame([], $this->evaluate($this->ctx(['ip' => '203.0.113.5']), $p)->stepUp, 'trusted network is enough');
        $this->assertSame([], $this->evaluate($this->ctx(['amr' => ['pwd', 'otp', 'mfa']]), $p)->stepUp, 'MFA is enough');

        $neither = $this->evaluate($this->ctx(), $p);
        $this->assertFalse($neither->blocked);
        $this->assertSame(['mfa'], $neither->stepUp, 'user can still step up');
    }

    public function test_or_with_only_unfixable_controls_blocks(): void
    {
        $p = $this->policy(['grant' => ['operator' => 'OR', 'controls' => ['trusted_network', 'compliant_device']]]);

        $this->assertTrue($this->evaluate($this->ctx(), $p)->blocked);
    }

    public function test_unknown_and_device_controls_fail_closed(): void
    {
        $this->assertTrue($this->evaluate($this->ctx(), $this->policy(['grant' => ['controls' => ['compliant_device']]]))->blocked);
        $this->assertTrue($this->evaluate($this->ctx(), $this->policy(['grant' => ['controls' => ['teleport']]]))->blocked);
    }

    public function test_a_policy_without_controls_changes_nothing(): void
    {
        $d = $this->evaluate($this->ctx(), $this->policy(['grant' => ['controls' => []]]));

        $this->assertFalse($d->blocked);
        $this->assertSame([], $d->stepUp);
        $this->assertCount(1, $d->applied);
    }

    // ── combination ───────────────────────────────────────────────────────

    public function test_step_ups_of_several_policies_are_merged_without_duplicates(): void
    {
        $d = $this->evaluate(
            $this->ctx(),
            $this->policy(['id' => 'a']),
            $this->policy(['id' => 'b']),
            $this->policy(['id' => 'c', 'grant' => ['controls' => ['phishing_resistant_mfa']]]),
        );

        $this->assertEqualsCanonicalizing(['mfa', 'phishing_resistant_mfa'], $d->stepUp);
    }

    public function test_the_strictest_session_max_age_wins(): void
    {
        $d = $this->evaluate(
            $this->ctx(['amr' => ['pwd', 'otp', 'mfa']]),
            $this->policy(['id' => 'a', 'session' => ['max_age_minutes' => 480]]),
            $this->policy(['id' => 'b', 'session' => ['max_age_minutes' => 60]]),
            $this->policy(['id' => 'c']),
        );

        $this->assertSame(60, $d->maxAgeMinutes);
    }

    public function test_priority_orders_the_applied_list(): void
    {
        $d = $this->evaluate($this->ctx(), $this->policy(['id' => 'late', 'priority' => 200]), $this->policy(['id' => 'early', 'priority' => 10]));

        $this->assertSame(['early', 'late'], array_column($d->applied, 'id'));
    }

    public function test_malformed_policies_do_not_crash_the_evaluation(): void
    {
        $d = (new PolicyEvaluator)->evaluate($this->ctx(), [
            [],
            ['state' => 'enabled'],
            ['state' => 'enabled', 'conditions' => 'nonsense', 'grant' => 'nonsense'],
            ['state' => 'enabled', 'grant' => ['controls' => 'mfa']],
        ], []);

        $this->assertFalse($d->blocked);
    }
}
