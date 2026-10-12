<?php

use EasySuite\Common\Oidc\BackChannelLogoutController;
use EasySuite\Common\Oidc\LoginController;
use Illuminate\Support\Facades\Route;

$prefix = trim(config('easysuite.login.route_prefix'), '/');

Route::middleware(config('easysuite.login.middleware'))->group(function () use ($prefix) {
    Route::get("{$prefix}/redirect", [LoginController::class, 'redirect'])->name('easysuite.login');
    Route::get("{$prefix}/callback", [LoginController::class, 'callback'])->name('easysuite.callback');
    Route::post("{$prefix}/logout", [LoginController::class, 'logout'])->name('easysuite.logout');

    if (config('easysuite.login.define_login_route')) {
        Route::get('login', [LoginController::class, 'login'])->name('login');
    }
});

// Server-zu-Server, ohne Session und ohne CSRF.
Route::middleware('throttle:60,1')
    ->post("{$prefix}/backchannel-logout", BackChannelLogoutController::class)
    ->name('easysuite.backchannel-logout');
