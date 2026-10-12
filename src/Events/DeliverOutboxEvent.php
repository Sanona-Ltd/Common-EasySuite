<?php

namespace EasySuite\Common\Events;

use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;

class DeliverOutboxEvent implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue;

    public int $tries = 1;

    public function __construct(public readonly string $outboxId) {}

    public function handle(OutboxDispatcher $dispatcher): void
    {
        if ($event = OutboxEvent::find($this->outboxId)) {
            $dispatcher->deliver($event);
        }
    }
}
