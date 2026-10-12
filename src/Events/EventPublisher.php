<?php

namespace EasySuite\Common\Events;

use Illuminate\Support\Facades\DB;

/**
 * Schreibt Events in die Outbox. Aufruf innerhalb derselben DB-Transaktion wie die Änderung:
 *
 *   DB::transaction(function () use ($user) {
 *       $user->update([...]);
 *       app(EventPublisher::class)->publish('user.updated', Subject::user($user->uuid), $user->tenant_id);
 *   });
 *
 * Die Auslieferung startet erst nach dem Commit.
 */
class EventPublisher
{
    /**
     * @param  array<string, mixed>  $subject  siehe Subject
     * @param  array<string, mixed>  $data  zusätzliche Felder (Thin Events: nur IDs/Gründe, keinen Zustand)
     * @return int Anzahl der angelegten Auslieferungen
     */
    public function publish(string $type, array $subject, ?string $tid = null, array $data = [], ?string $txn = null): int
    {
        $uri = EventTypes::resolve($type);
        $payload = ['subject' => $subject, 'event_timestamp' => time()] + $data;
        $txn ??= request()?->header('X-Request-Id');

        $ids = [];
        foreach ((array) config('easysuite.events.subscriptions') as $subscription) {
            if (! $this->matches($subscription['events'] ?? ['*'], $type, $uri)) {
                continue;
            }

            $ids[] = OutboxEvent::create([
                'event_type' => $uri,
                'tid' => $tid,
                'txn' => $txn,
                'payload' => $payload,
                'audience' => rtrim($subscription['audience'], '/'),
                's2s_audience' => $subscription['s2s_audience'] ?? null,
                'endpoint' => $subscription['endpoint'],
                'status' => OutboxEvent::PENDING,
                'next_attempt_at' => now(),
            ])->id;
        }

        foreach ($ids as $id) {
            DB::afterCommit(fn () => DeliverOutboxEvent::dispatch($id));
        }

        return count($ids);
    }

    /** @param string[] $filter */
    private function matches(array $filter, string $type, string $uri): bool
    {
        return in_array('*', $filter, true) || in_array($type, $filter, true) || in_array($uri, $filter, true);
    }
}
