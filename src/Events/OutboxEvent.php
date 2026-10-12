<?php

namespace EasySuite\Common\Events;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;

/**
 * @property string $id
 * @property string $event_type
 * @property ?string $tid
 * @property ?string $txn
 * @property array $payload
 * @property string $audience
 * @property ?string $s2s_audience
 * @property string $endpoint
 * @property string $status
 * @property int $attempts
 */
class OutboxEvent extends Model
{
    use HasUuids;

    public const PENDING = 'pending';

    public const DELIVERED = 'delivered';

    public const DEAD = 'dead';

    protected $table = 'easysuite_event_outbox';

    protected $guarded = [];

    protected function casts(): array
    {
        return [
            'payload' => 'array',
            'next_attempt_at' => 'datetime',
            'delivered_at' => 'datetime',
        ];
    }
}
