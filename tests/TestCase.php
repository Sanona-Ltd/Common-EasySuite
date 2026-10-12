<?php

namespace EasySuite\Common\Tests;

use EasySuite\Common\EasySuiteServiceProvider;
use EasySuite\Common\Testing\FakeAuthServer;
use Orchestra\Testbench\TestCase as Orchestra;

abstract class TestCase extends Orchestra
{
    protected FakeAuthServer $auth;

    protected function getPackageProviders($app): array
    {
        return [EasySuiteServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.key', 'base64:'.base64_encode(random_bytes(32)));
        $app['config']->set('app.url', 'https://app.test');
        $app['config']->set('cache.default', 'array');
        $app['config']->set('database.default', 'testing');
        $app['config']->set('database.connections.testing', ['driver' => 'sqlite', 'database' => ':memory:']);
        $app['config']->set('queue.default', 'sync');
        $app['config']->set('easysuite.self.url', 'https://app.test');
        $app['config']->set('easysuite.login.user_model', TestUser::class);
    }

    protected function defineDatabaseMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__.'/../database/migrations');
        $this->loadMigrationsFrom(__DIR__.'/migrations');
    }

    protected function setUp(): void
    {
        parent::setUp();

        $this->auth = FakeAuthServer::install();
    }
}
