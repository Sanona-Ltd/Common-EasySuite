<?php

namespace EasySuite\Common\Support;

/** Hält die Tenant-ID (`tid`) des aktuellen Requests. Wird von `easysuite.token` gesetzt. */
class TenantContext
{
    private ?string $tenantId = null;

    public function set(?string $tenantId): void
    {
        $this->tenantId = $tenantId;
    }

    public function id(): ?string
    {
        return $this->tenantId;
    }

    public function has(): bool
    {
        return $this->tenantId !== null;
    }
}
