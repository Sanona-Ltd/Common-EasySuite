<?php

namespace EasySuite\Common\Events;

/** Ein einzelnes, bereits verifiziertes Event aus einem SET. */
final class ReceivedEvent
{
    /** @param array<string, mixed> $payload */
    public function __construct(
        public readonly string $type,
        public readonly array $payload,
        public readonly ?string $tid,
        public readonly string $jti,
        public readonly ?string $txn,
        public readonly string $issuer,
        public readonly int $issuedAt,
    ) {}

    public function name(): string
    {
        return EventTypes::shortName($this->type);
    }

    /** @return array<string, mixed> */
    public function subject(): array
    {
        return (array) ($this->payload['subject'] ?? []);
    }

    /** `sub` (User) oder `id` (opaque). */
    public function subjectId(): ?string
    {
        return $this->subject()['sub'] ?? $this->subject()['id'] ?? null;
    }

    public function get(string $key, mixed $default = null): mixed
    {
        return $this->payload[$key] ?? $default;
    }
}
