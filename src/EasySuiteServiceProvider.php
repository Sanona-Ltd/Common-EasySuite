<?php

namespace EasySuite\Common;

use EasySuite\Common\Events\DispatchOutboxCommand;
use EasySuite\Common\Events\EventPublisher;
use EasySuite\Common\Events\EventRegistry;
use EasySuite\Common\Events\OutboxDispatcher;
use EasySuite\Common\Events\SessionRevocationHandler;
use EasySuite\Common\Events\SetSigner;
use EasySuite\Common\Events\SetVerifier;
use EasySuite\Common\Http\Middleware\EnforceSession;
use EasySuite\Common\Http\Middleware\RequireSaasAdmin;
use EasySuite\Common\Http\Middleware\RequireScope;
use EasySuite\Common\Http\Middleware\RequireToken;
use EasySuite\Common\Http\Middleware\RequireTokenType;
use EasySuite\Common\Jwt\JwksProvider;
use EasySuite\Common\Jwt\TokenVerifier;
use EasySuite\Common\Oidc\OidcClient;
use EasySuite\Common\Oidc\RevokedSessions;
use EasySuite\Common\Oidc\UserProvisioner;
use EasySuite\Common\S2S\Client;
use EasySuite\Common\S2S\ConsoleAccess;
use EasySuite\Common\Support\Clock;
use EasySuite\Common\Support\DoctorCommand;
use EasySuite\Common\Support\PullEnvCommand;
use EasySuite\Common\Support\TenantContext;
use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Http\Client\Factory as Http;
use Illuminate\Routing\Router;
use Illuminate\Support\ServiceProvider;

class EasySuiteServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/easysuite.php', 'easysuite');

        $this->app->singletonIf(Http::class);
        $this->app->singleton(Clock::class);
        $this->app->singleton(TenantContext::class);

        $this->app->singleton(JwksProvider::class, fn ($app) => new JwksProvider(
            $app->make(Http::class), $this->cache(), (int) config('easysuite.jwks_cache_ttl')
        ));
        $this->app->singleton(TokenVerifier::class, fn ($app) => new TokenVerifier(
            $app->make(JwksProvider::class), $app->make(Clock::class), (int) config('easysuite.leeway')
        ));
        $this->app->singleton(RevokedSessions::class, fn () => new RevokedSessions(
            $this->cache(), (int) config('easysuite.revocation_ttl')
        ));
        $this->app->singleton(OidcClient::class, fn ($app) => new OidcClient($app->make(Http::class), $this->cache()));
        $this->app->singleton(Client::class, fn ($app) => new Client(
            $app->make(Http::class), $this->cache(), $app->make(OidcClient::class)
        ));

        $this->app->singleton(ConsoleAccess::class, fn ($app) => new ConsoleAccess($app->make(Client::class), $this->cache()));

        $this->app->bind(UserProvisioner::class, fn () => app(config('easysuite.login.provisioner')));

        $this->app->singleton(SetSigner::class);
        $this->app->singleton(SetVerifier::class);
        $this->app->singleton(EventPublisher::class);
        $this->app->singleton(EventRegistry::class);
        $this->app->singleton(OutboxDispatcher::class);
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../config/easysuite.php' => config_path('easysuite.php')], 'easysuite-config');
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');

        $router = $this->app->make(Router::class);
        $router->aliasMiddleware('easysuite.token', RequireToken::class);
        $router->aliasMiddleware('easysuite.scope', RequireScope::class);
        $router->aliasMiddleware('easysuite.type', RequireTokenType::class);
        $router->aliasMiddleware('easysuite.saas-admin', RequireSaasAdmin::class);
        $router->aliasMiddleware('easysuite.session', EnforceSession::class);

        if ($this->app->runningInConsole()) {
            $this->commands([DispatchOutboxCommand::class, PullEnvCommand::class, DoctorCommand::class]);
        }

        if (config('easysuite.login.enabled')) {
            $this->loadRoutesFrom(__DIR__.'/../routes/oidc.php');
        }

        if (config('easysuite.events.enabled')) {
            $this->loadRoutesFrom(__DIR__.'/../routes/events.php');

            if (config('easysuite.events.builtin_handlers')) {
                $registry = $this->app->make(EventRegistry::class);
                $registry->on(['session.revoked', 'user.disabled'], SessionRevocationHandler::class);
            }
        }
    }

    private function cache(): CacheRepository
    {
        return $this->app->make('cache')->store(config('easysuite.cache_store'));
    }
}
