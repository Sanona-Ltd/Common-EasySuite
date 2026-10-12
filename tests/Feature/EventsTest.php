<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\Events\EventPublisher;
use EasySuite\Common\Events\EventRegistry;
use EasySuite\Common\Events\EventTypes;
use EasySuite\Common\Events\OutboxEvent;
use EasySuite\Common\Events\ReceivedEvent;
use EasySuite\Common\Events\SetSigner;
use EasySuite\Common\Events\SetVerifier;
use EasySuite\Common\Events\Subject;
use EasySuite\Common\Jwt\InvalidTokenException;
use EasySuite\Common\Jwt\Jwk;
use EasySuite\Common\Jwt\TokenVerifier;
use EasySuite\Common\Oidc\RevokedSessions;
use EasySuite\Common\Testing\Rsa;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Http;

class EventsTest extends TestCase
{
    private function generateSigningKey(): void
    {
        config(['easysuite.events.signing_key' => Rsa::generate()['private']]);
    }

    private function receive(string $set, ?string $bearer = null)
    {
        return $this->call('POST', '/s2s/events', [], [], [], [
            'HTTP_AUTHORIZATION' => 'Bearer '.($bearer ?? $this->auth->appToken()),
            'CONTENT_TYPE' => 'application/secevent+jwt',
        ], $set);
    }

    private function trustAuth(): void
    {
        config(['easysuite.events.trusted_issuers' => ['https://auth.test' => 'https://auth.test/.well-known/jwks.json']]);
    }

    public function test_event_types_resolve_short_names_and_round_trip(): void
    {
        $this->assertSame(EventTypes::SESSION_REVOKED, EventTypes::resolve('session.revoked'));
        $this->assertSame('https://schemas.easysuite.ch/event/tenant/created', EventTypes::resolve('tenant.created'));
        $this->assertSame('tenant.created', EventTypes::shortName('https://schemas.easysuite.ch/event/tenant/created'));
        $this->assertSame('user.disabled', EventTypes::shortName(EventTypes::ACCOUNT_DISABLED));
        $this->assertSame('https://x/y', EventTypes::resolve('https://x/y'));
    }

    public function test_signer_and_verifier_round_trip(): void
    {
        $this->generateSigningKey();
        $signer = app(SetSigner::class);
        config(['easysuite.events.trusted_issuers' => ['https://app.test' => 'https://app.test/.well-known/jwks.json']]);
        Http::fake(['https://app.test/.well-known/jwks.json' => Http::response(['keys' => [Jwk::fromPublicPem($signer->publicPem())]])]);

        $jwt = $signer->sign(
            'https://app.test',
            [EventTypes::resolve('tenant.created') => ['subject' => Subject::tenant('t-1'), 'reason' => 'x']],
            'tenant-1',
            'txn-1',
            'jti-1'
        );

        $events = app(SetVerifier::class)->verify($jwt);

        $this->assertCount(1, $events);
        $this->assertSame('tenant.created', $events[0]->name());
        $this->assertSame('t-1', $events[0]->subjectId());
        $this->assertSame('x', $events[0]->get('reason'));
        $this->assertSame('tenant-1', $events[0]->tid);
        $this->assertSame('txn-1', $events[0]->txn);
        $this->assertSame('jti-1', $events[0]->jti);
    }

    public function test_verifier_rejects_untrusted_issuer_wrong_audience_wrong_typ_and_stale_events(): void
    {
        $this->trustAuth();
        $verify = fn (string $jwt) => app(SetVerifier::class)->verify($jwt);
        $events = [EventTypes::ACCOUNT_DISABLED => ['subject' => ['sub' => 'u']]];

        $cases = [
            'untrusted issuer' => $this->auth->set($events, 'https://app.test', ['iss' => 'https://evil.test']),
            'wrong audience' => $this->auth->set($events, 'https://other.test'),
            'stale' => $this->auth->set($events, 'https://app.test', ['iat' => time() - 3600]),
            'future' => $this->auth->set($events, 'https://app.test', ['iat' => time() + 3600]),
            'no jti' => $this->auth->sign(['iss' => 'https://auth.test', 'aud' => 'https://app.test', 'iat' => time(), 'events' => $events], ['typ' => 'secevent+jwt']),
            'wrong typ' => $this->auth->sign(['iss' => 'https://auth.test', 'aud' => 'https://app.test', 'iat' => time(), 'jti' => 'x', 'events' => $events]),
        ];

        foreach ($cases as $name => $jwt) {
            try {
                $verify($jwt);
                $this->fail("{$name} was accepted");
            } catch (InvalidTokenException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_receiver_dispatches_to_handlers_once_per_jti(): void
    {
        $this->trustAuth();
        $seen = [];
        app(EventRegistry::class)->on('tenant.created', function (ReceivedEvent $e) use (&$seen) {
            $seen[] = [$e->subjectId(), $e->tid, $e->issuer];
        });

        $set = $this->auth->set(
            [EventTypes::resolve('tenant.created') => ['subject' => Subject::tenant('t-1')]],
            'https://app.test',
            ['tid' => 'tenant-1']
        );

        $this->receive($set)->assertStatus(202);
        $this->receive($set)->assertStatus(202); // Wiederholung: bestätigt, aber nicht erneut verarbeitet

        $this->assertSame([['t-1', 'tenant-1', 'https://auth.test']], $seen);
    }

    public function test_receiver_unknown_event_types_are_acknowledged_and_ignored(): void
    {
        $this->trustAuth();

        $this->receive($this->auth->set(['https://schemas.easysuite.ch/event/foo/bar' => ['subject' => []]], 'https://app.test'))
            ->assertStatus(202);
    }

    public function test_receiver_requires_an_app_token(): void
    {
        $this->trustAuth();
        $set = $this->auth->set([EventTypes::ACCOUNT_DISABLED => ['subject' => ['sub' => 'u']]], 'https://app.test');

        $this->receive($set, $this->auth->accessToken())->assertForbidden();
        $this->call('POST', '/s2s/events', [], [], [], ['CONTENT_TYPE' => 'application/secevent+jwt'], $set)->assertUnauthorized();
    }

    public function test_receiver_rejects_invalid_sets_with_400(): void
    {
        $this->trustAuth();

        $this->receive('garbage')->assertStatus(400);
        $this->receive($this->auth->set([], 'https://app.test', ['iss' => 'https://evil.test']))->assertStatus(400);
    }

    public function test_failing_handler_returns_500_and_allows_a_retry(): void
    {
        $this->trustAuth();
        $this->withoutExceptionHandling();
        $calls = 0;
        app(EventRegistry::class)->on('tenant.created', function () use (&$calls) {
            if (++$calls === 1) {
                throw new \RuntimeException('boom');
            }
        });
        $set = $this->auth->set([EventTypes::resolve('tenant.created') => ['subject' => []]], 'https://app.test');

        try {
            $this->receive($set);
            $this->fail('Handler exception was swallowed');
        } catch (\RuntimeException) {
            $this->addToAssertionCount(1);
        }

        $this->receive($set)->assertStatus(202);
        $this->assertSame(2, $calls);
    }

    public function test_builtin_handlers_fill_the_revocation_list(): void
    {
        $this->trustAuth();
        $revoked = app(RevokedSessions::class);

        $this->receive($this->auth->set([EventTypes::SESSION_REVOKED => ['subject' => Subject::user('u1'), 'sid' => 'sid-77']], 'https://app.test'))->assertStatus(202);
        $this->assertTrue($revoked->isSessionRevoked('sid-77'));

        $this->receive($this->auth->set([EventTypes::ACCOUNT_DISABLED => ['subject' => Subject::user('u2')]], 'https://app.test'))->assertStatus(202);
        $this->assertTrue($revoked->isSubjectRevoked('u2', time()));
        $this->assertFalse($revoked->isSubjectRevoked('u3', time()));
    }

    public function test_publishing_writes_matching_subscriptions_and_delivers_a_verifiable_set(): void
    {
        $this->generateSigningKey();
        config([
            'easysuite.events.subscriptions' => [
                ['audience' => 'https://orbis.test/', 'endpoint' => 'https://orbis.test/s2s/events', 's2s_audience' => 'orbis-client', 'events' => ['tenant.created']],
                ['audience' => 'https://billing.test', 'endpoint' => 'https://billing.test/s2s/events', 'events' => ['invoice.paid']],
            ],
        ]);
        Http::fake(['https://orbis.test/*' => Http::response('', 202)]);

        $count = app(EventPublisher::class)->publish('tenant.created', Subject::tenant('t-1'), 'tenant-1', ['why' => 'test']);

        $this->assertSame(1, $count);
        $outbox = OutboxEvent::sole();
        $this->assertSame(OutboxEvent::DELIVERED, $outbox->status);
        $this->assertSame('https://orbis.test', $outbox->audience);

        Http::assertSent(function (Request $request) use ($outbox) {
            if ($request->url() !== 'https://orbis.test/s2s/events') {
                return false;
            }

            $this->assertSame('application/secevent+jwt', $request->header('Content-Type')[0]);

            // Bearer: S2S-Token für den Empfänger.
            $bearer = str_replace('Bearer ', '', $request->header('Authorization')[0]);
            $access = app(TokenVerifier::class)->verify($bearer, 'https://auth.test', 'https://auth.test/.well-known/jwks.json', 'orbis-client');
            $this->assertTrue($access->hasScope('events:send'));

            // Body: SET mit der Outbox-ID als jti, signiert mit unserem Key.
            $claims = app(TokenVerifier::class)->unverifiedClaims($request->body());
            $this->assertSame($outbox->id, $claims['jti']);
            $this->assertSame('https://app.test', $claims['iss']);
            $this->assertSame(['https://orbis.test'], $claims['aud']);
            $this->assertSame('t-1', $claims['events'][EventTypes::resolve('tenant.created')]['subject']['id']);
            $this->assertSame('test', $claims['events'][EventTypes::resolve('tenant.created')]['why']);

            return true;
        });
    }

    public function test_wildcard_subscription_matches_everything(): void
    {
        config(['easysuite.events.subscriptions' => [['audience' => 'https://a.test', 'endpoint' => 'https://a.test/e', 'events' => ['*']]]]);
        Http::fake(['https://a.test/*' => Http::response('', 202)]);
        $this->generateSigningKey();

        $this->assertSame(1, app(EventPublisher::class)->publish('anything.happened', []));
    }

    public function test_failed_delivery_is_retried_with_backoff_and_ends_dead(): void
    {
        $this->generateSigningKey();
        config([
            'easysuite.events.backoff' => [60],
            'easysuite.events.subscriptions' => [['audience' => 'https://a.test', 'endpoint' => 'https://a.test/e', 'events' => ['*']]],
        ]);
        Http::fake(['https://a.test/*' => Http::response('down', 503)]);

        app(EventPublisher::class)->publish('tenant.updated', []);

        $event = OutboxEvent::sole();
        $this->assertSame(OutboxEvent::PENDING, $event->status);
        $this->assertSame(1, $event->attempts);
        $this->assertStringContainsString('503', $event->last_error);
        $this->assertTrue($event->next_attempt_at->isFuture());

        // Noch nicht fällig: der Befehl fasst es nicht an.
        Artisan::call('easysuite:events:dispatch');
        $this->assertSame(1, $event->fresh()->attempts);

        // Fällig: zweiter (und letzter) Versuch → dead.
        $event->update(['next_attempt_at' => now()->subSecond()]);
        $this->assertSame(1, Artisan::call('easysuite:events:dispatch'));

        $event->refresh();
        $this->assertSame(OutboxEvent::DEAD, $event->status);
        $this->assertSame(2, $event->attempts);
    }

    public function test_permanent_client_errors_go_dead_immediately(): void
    {
        $this->generateSigningKey();
        config(['easysuite.events.subscriptions' => [['audience' => 'https://a.test', 'endpoint' => 'https://a.test/e', 'events' => ['*']]]]);
        Http::fake(['https://a.test/*' => Http::response('no', 400)]);

        app(EventPublisher::class)->publish('tenant.updated', []);

        $this->assertSame(OutboxEvent::DEAD, OutboxEvent::sole()->status);
    }

    public function test_jwks_endpoint_publishes_the_own_key(): void
    {
        $this->generateSigningKey();

        $response = $this->getJson('/.well-known/jwks.json')->assertOk();

        $this->assertSame(app(SetSigner::class)->keyId(), $response->json('keys.0.kid'));
        $this->assertSame('RS256', $response->json('keys.0.alg'));
    }

    public function test_jwks_endpoint_is_404_without_a_key(): void
    {
        $this->getJson('/.well-known/jwks.json')->assertNotFound();
    }

    public function test_sign_claims_issues_a_verifiable_bundle_style_token(): void
    {
        $this->generateSigningKey();
        $signer = app(SetSigner::class);
        config(['easysuite.services.security.url' => 'https://app.test', 'easysuite.self.url' => 'https://app.test']);
        Http::fake(['https://app.test/.well-known/jwks.json' => Http::response(['keys' => [Jwk::fromPublicPem($signer->publicPem())]])]);

        $jwt = $signer->signClaims('https://app.test', ['tid' => 't1', 'version' => 3, 'policies' => [], 'iss' => 'https://evil.test', 'sub' => 'forged']);

        $token = app(TokenVerifier::class)->verify($jwt, 'https://app.test', 'https://app.test/.well-known/jwks.json', 'https://app.test', 30, false);

        $this->assertSame('t1', $token->tid());
        $this->assertSame(3, $token->claim('version'));
        $this->assertSame('https://app.test', $token->issuer(), 'iss cannot be overridden by the claims');
        $this->assertNull($token->sub(), 'registered claims from the caller are ignored');
        $this->assertSame($signer->keyId(), $token->header('kid'));
    }
}
