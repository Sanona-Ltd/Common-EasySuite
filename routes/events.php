<?php

use EasySuite\Common\Events\JwksController;
use EasySuite\Common\Events\ReceiveEventsController;
use Illuminate\Support\Facades\Route;

Route::post(trim(config('easysuite.events.route_prefix'), '/').'/events', ReceiveEventsController::class)
    ->middleware(['easysuite.token', 'easysuite.type:app', 'throttle:600,1'])
    ->name('easysuite.events.receive');

if (config('easysuite.events.publish_jwks')) {
    Route::get('.well-known/jwks.json', JwksController::class)->name('easysuite.events.jwks');
}
