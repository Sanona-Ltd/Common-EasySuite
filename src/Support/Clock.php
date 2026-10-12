<?php

namespace EasySuite\Common\Support;

use DateTimeImmutable;
use Illuminate\Support\Carbon;
use Psr\Clock\ClockInterface;

/** PSR-20 Uhr auf Basis von Carbon, damit `Carbon::setTestNow()` in Tests greift. */
class Clock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return Carbon::now('UTC')->toDateTimeImmutable();
    }
}
