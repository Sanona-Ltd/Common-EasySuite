<?php

namespace EasySuite\Common\Events;

use EasySuite\Common\S2S\Client;
use Illuminate\Http\Client\Factory as Http;
use Throwable;

/** Liefert einen Outbox-Eintrag aus (at-least-once, Backoff, danach `dead`). */
class OutboxDispatcher
{
    public function __construct(
        private readonly SetSigner $signer,
        private readonly Client $s2s,
        private readonly Http $http,
    ) {}

    public function deliver(OutboxEvent $event): void
    {
        if ($event->status !== OutboxEvent::PENDING) {
            return;
        }

        $scopes = [(string) config('easysuite.events.send_scope')];
        $event->attempts++;

        try {
            $set = $this->signer->sign(
                $event->audience,
                [$event->event_type => $event->payload],
                $event->tid,
                $event->txn,
                $event->id,
            );

            $token = $event->s2s_audience
                ? $this->s2s->tokenForAudience($event->s2s_audience, $scopes)
                : null;

            $request = $this->http->acceptJson()->timeout(10)->withBody($set, 'application/secevent+jwt');
            $response = ($token ? $request->withToken($token) : $request)->post($event->endpoint);
        } catch (Throwable $e) {
            $this->failed($event, $e->getMessage(), retry: true);

            return;
        }

        if ($response->successful()) {
            $event->forceFill([
                'status' => OutboxEvent::DELIVERED,
                'delivered_at' => now(),
                'last_error' => null,
            ])->save();

            return;
        }

        if ($response->status() === 401 && $event->s2s_audience) {
            $this->s2s->forgetAudience($event->s2s_audience, $scopes);
        }

        // 4xx (ausser 401/408/429) bedeutet: der Empfänger lehnt das Event endgültig ab.
        $retry = ! ($response->clientError() && ! in_array($response->status(), [401, 408, 429], true));
        $this->failed($event, 'HTTP '.$response->status().' '.mb_substr($response->body(), 0, 500), $retry);
    }

    private function failed(OutboxEvent $event, string $error, bool $retry): void
    {
        $backoff = array_values((array) config('easysuite.events.backoff'));

        if (! $retry || $event->attempts > count($backoff)) {
            $event->forceFill(['status' => OutboxEvent::DEAD, 'last_error' => $error, 'next_attempt_at' => null])->save();

            return;
        }

        $event->forceFill([
            'last_error' => $error,
            'next_attempt_at' => now()->addSeconds($backoff[$event->attempts - 1]),
        ])->save();
    }
}
