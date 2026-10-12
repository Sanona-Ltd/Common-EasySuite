<?php

namespace EasySuite\Common\Events;

/**
 * Registriert Handler für eingehende Events:
 *
 *   app(EventRegistry::class)->on('tenant.created', fn (ReceivedEvent $e) => SyncTenant::dispatch($e->subjectId()));
 *   app(EventRegistry::class)->on(['group.changed', 'role.changed'], InvalidatePermissionCache::class);
 *
 * Handler laufen synchron im Request des Senders und müssen kurz sein (schwere Arbeit in einen Job geben).
 * Wirft ein Handler, antwortet der Empfänger mit 500 und der Sender wiederholt.
 */
class EventRegistry
{
    /** @var array<string, array<int, callable|string>> */
    private array $handlers = [];

    /**
     * @param  string|string[]  $types  Kurzname, URI oder '*'
     * @param  callable|class-string  $handler  Klasse mit __invoke(ReceivedEvent)
     */
    public function on(string|array $types, callable|string $handler): void
    {
        foreach ((array) $types as $type) {
            $key = $type === '*' ? '*' : EventTypes::resolve($type);
            $this->handlers[$key][] = $handler;
        }
    }

    public function dispatch(ReceivedEvent $event): void
    {
        foreach ([...($this->handlers[$event->type] ?? []), ...($this->handlers['*'] ?? [])] as $handler) {
            is_string($handler) ? app($handler)($event) : $handler($event);
        }
    }
}
