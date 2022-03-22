<?php

use Mmeyer2k\LaravelSqliGuard\ServiceProvider;
use Mmeyer2k\LaravelSqliGuard\SqliProtection;

class TestCase extends \Orchestra\Testbench\TestCase
{
    public function testSingleQuoteBlock()
    {
        \DB::statement("select 'asdf'");
    }

    protected function setUp(): void
    {
        parent::setUp();

        SqliProtection::blockUnsafe();
    }

    protected function getPackageProviders($app): array
    {
        return [ServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('database.default', 'mysql');
        $app['config']->set('database.connections.mysql.username', 'root');
        $app['config']->set('database.connections.mysql.password', '');
    }
}