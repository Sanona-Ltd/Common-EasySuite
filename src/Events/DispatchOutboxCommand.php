<?php

namespace EasySuite\Common\Events;

use Illuminate\Console\Command;

/** Wiederholt fällige Auslieferungen. Im Scheduler jede Minute einplanen: Schedule::command('easysuite:events:dispatch')->everyMinute(); */
class DispatchOutboxCommand extends Command
{
    protected $signature = 'easysuite:events:dispatch {--limit=100}';

    protected $description = 'Liefert fällige Events aus der Outbox aus (inkl. Wiederholungen).';

    public function handle(OutboxDispatcher $dispatcher): int
    {
        $events = OutboxEvent::query()
            ->where('status', OutboxEvent::PENDING)
            ->where('next_attempt_at', '<=', now())
            ->orderBy('next_attempt_at')
            ->limit((int) $this->option('limit'))
            ->get();

        foreach ($events as $event) {
            $dispatcher->deliver($event);
        }

        $dead = OutboxEvent::where('status', OutboxEvent::DEAD)->count();
        $this->info("{$events->count()} Events verarbeitet, {$dead} dead.");

        return $dead > 0 ? self::FAILURE : self::SUCCESS;
    }
}
