<?php

namespace EasySuite\Common\Support;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;

/**
 * Trait für tenant-gebundene Models: filtert Abfragen automatisch auf die `tid` des Requests
 * und setzt `tenant_id` beim Anlegen. Ohne gesetzten Kontext (Konsole, Queue) wird nicht gefiltert,
 * dort ist `withoutGlobalScopes()` bzw. explizites `where('tenant_id', …)` Pflicht.
 */
trait BelongsToTenant
{
    protected static function bootBelongsToTenant(): void
    {
        static::addGlobalScope('tenant', function (Builder $query) {
            $context = app(TenantContext::class);

            if ($context->has()) {
                $query->where($query->getModel()->getTable().'.tenant_id', $context->id());
            }
        });

        static::creating(function (Model $model) {
            $context = app(TenantContext::class);

            if ($model->getAttribute('tenant_id') === null && $context->has()) {
                $model->setAttribute('tenant_id', $context->id());
            }
        });
    }
}
