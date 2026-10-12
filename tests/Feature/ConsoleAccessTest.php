<?php

namespace EasySuite\Common\Tests\Feature;

use EasySuite\Common\S2S\ConsoleAccess;
use EasySuite\Common\Tests\TestCase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;

class ConsoleAccessTest extends TestCase
{
    /** What Orbis answers; tests change it. */
    private array $orbis = ['status' => 200, 'access' => ['orbis' => 'admin', 'security' => 'reader', 'billing' => null]];

    protected function setUp(): void
    {
        parent::setUp();

        config(['easysuite.services.orbis' => ['url' => 'https://orbis.test', 'audience' => 'orbis-client']]);
        Http::fake(['https://orbis.test/*' => fn () => $this->orbis['status'] === 200
            ? Http::response(['sub' => 'u1', 'tid' => 't1', 'access' => $this->orbis['access']])
            : Http::response('', $this->orbis['status'])]);
    }

    private function asked(): int
    {
        return Http::recorded(fn (Request $r) => str_contains($r->url(), '/access'))->count();
    }

    public function test_the_role_per_app_comes_from_orbis(): void
    {
        $access = app(ConsoleAccess::class);

        $this->assertSame('reader', $access->role('security', 'u1'));
        $this->assertNull($access->role('billing', 'u1'));
        $this->assertNull($access->role('crm', 'u1'));

        Http::assertSent(fn (Request $r) => $r->url() === 'https://orbis.test/s2s/users/u1/access' && $r->hasHeader('Authorization'));
    }

    public function test_the_answer_is_reused_for_a_short_while_then_asked_again(): void
    {
        $access = app(ConsoleAccess::class);

        $access->role('security', 'u1');
        $access->role('security', 'u1');
        $this->assertSame(1, $this->asked());

        $this->orbis['access'] = ['security' => 'admin'];
        Carbon::setTestNow(now()->addSeconds(61));

        $this->assertSame('admin', $access->role('security', 'u1'), 'a change applies within the minute');
        $this->assertSame(2, $this->asked());
    }

    public function test_forget_makes_the_next_request_ask_again(): void
    {
        $access = app(ConsoleAccess::class);
        $access->role('security', 'u1');

        $this->orbis['access'] = ['security' => null];
        $access->forget('u1');

        $this->assertNull($access->role('security', 'u1'));
    }

    public function test_a_user_orbis_does_not_know_has_no_access(): void
    {
        $this->orbis['status'] = 404;

        $this->assertNull(app(ConsoleAccess::class)->role('security', 'ghost'));
    }

    public function test_anything_that_is_not_a_known_role_counts_as_none(): void
    {
        $this->orbis['access'] = ['security' => 'owner', 'billing' => 'admin'];

        $access = app(ConsoleAccess::class);

        $this->assertNull($access->role('security', 'u1'));
        $this->assertSame('admin', $access->role('billing', 'u1'));
    }

    public function test_when_orbis_is_down_the_last_known_answer_still_counts_for_a_while(): void
    {
        $access = app(ConsoleAccess::class);
        $this->assertSame('reader', $access->role('security', 'u1'));

        $this->orbis['status'] = 503;
        Carbon::setTestNow(now()->addMinutes(10));

        $this->assertSame('reader', $access->role('security', 'u1'));
    }

    public function test_when_orbis_is_down_and_nothing_is_known_there_is_no_access(): void
    {
        $this->orbis['status'] = 503;

        $this->assertNull(app(ConsoleAccess::class)->role('security', 'u1'));
    }

    public function test_the_stale_answer_does_not_outlive_its_limit(): void
    {
        $access = app(ConsoleAccess::class);
        $access->role('security', 'u1');

        $this->orbis['status'] = 503;
        Carbon::setTestNow(now()->addHours(2));

        $this->assertNull($access->role('security', 'u1'));
    }
}
