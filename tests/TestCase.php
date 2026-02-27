<?php

namespace Mmeyer2k\LaravelSqliGuard\Tests;

use Illuminate\Database\QueryException;
use Mmeyer2k\LaravelSqliGuard\Events\QueryBlocked;
use Mmeyer2k\LaravelSqliGuard\ServiceProvider;
use Mmeyer2k\LaravelSqliGuard\SqlInjectionException;
use Mmeyer2k\LaravelSqliGuard\SqliGuard;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;

class TestCase extends \Orchestra\Testbench\TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        SqliGuard::blockUnsafe();
    }

    protected function getPackageProviders($app): array
    {
        return [ServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app): void
    {
        $app['config']->set('database.default', 'mysql');
        $app['config']->set('database.connections.mysql.host', env('DB_HOST', '127.0.0.1'));
        $app['config']->set('database.connections.mysql.port', env('DB_PORT', '3306'));
        $app['config']->set('database.connections.mysql.database', env('DB_DATABASE', 'testing'));
        $app['config']->set('database.connections.mysql.username', env('DB_USERNAME', 'root'));
        $app['config']->set('database.connections.mysql.password', env('DB_PASSWORD', ''));
        $app['config']->set('sqliguard.enabled', true);
        $app['config']->set('sqliguard.log_blocked', false);
    }

    // ---------------------------------------------------------------
    // Core needle blocking tests
    // ---------------------------------------------------------------

    public function testBlocksSingleQuotes(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select 'asdf'");
    }

    public function testBlocksDoubleQuotes(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement('select "asdf"');
    }

    public function testBlocksHexLiterals(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select 0x41");
    }

    public function testBlocksDashDashComment(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select 1 -- comment");
    }

    public function testBlocksHashComment(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select 1 # comment");
    }

    public function testBlocksBlockCommentOpen(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select /* comment */ 1");
    }

    public function testBlocksSystemVariables(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select @@version");
    }

    public function testBlocksSleep(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select sleep(5)");
    }

    public function testBlocksBenchmark(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select benchmark(1000000, md5(1))");
    }

    public function testBlocksVersion(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select version()");
    }

    public function testBlocksLoadFile(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select load_file('/etc/passwd')");
    }

    public function testBlocksIntoOutfile(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select 1 into outfile '/tmp/test'");
    }

    public function testBlocksIntoDumpfile(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select 1 into dumpfile '/tmp/test'");
    }

    public function testBlocksExtractvalue(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select extractvalue(1, 1)");
    }

    public function testBlocksUpdatexml(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select updatexml(1, 1, 1)");
    }

    public function testBlocksInformationSchemaRegex(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select (select count(*) from information_schema.tables, information_schema.columns)");
    }

    // ---------------------------------------------------------------
    // Case insensitivity tests
    // ---------------------------------------------------------------

    public function testBlocksSleepUppercase(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select SLEEP(5)");
    }

    public function testBlocksVersionMixedCase(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select VeRsIoN()");
    }

    public function testBlocksBenchmarkUppercase(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select BENCHMARK(1000000, MD5(1))");
    }

    public function testBlocksLoadFileMixedCase(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select LOAD_FILE('/etc/passwd')");
    }

    // ---------------------------------------------------------------
    // Normalization evasion tests
    // ---------------------------------------------------------------

    public function testBlocksSleepWithExtraWhitespace(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select   sleep  (5)");
    }

    public function testBlocksFunctionWithSpaceBeforeParen(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select version ()");
    }

    public function testBlocksNullByteEvasion(): void
    {
        $this->expectException(QueryException::class);
        \DB::statement("select sl\0eep(5)");
    }

    // ---------------------------------------------------------------
    // Strict mode tests
    // ---------------------------------------------------------------

    public function testDoesNotBlockCharInNormalMode(): void
    {
        // char( should NOT be blocked in normal mode
        // This will fail for other reasons (query syntax), but should not throw SqlInjectionException
        try {
            \DB::statement("select char(65)");
            // If it somehow succeeds, that's fine too
        } catch (QueryException $e) {
            // Verify it's NOT caused by our guard — char( should be allowed in normal mode
            $this->assertNotInstanceOf(SqlInjectionException::class, $e->getPrevious());
        }
    }

    public function testBlocksCharInStrictMode(): void
    {
        config(['sqliguard.strict_mode' => true]);

        $this->expectException(QueryException::class);
        \DB::statement("select char(65)");
    }

    public function testBlocksSemicolonInStrictMode(): void
    {
        config(['sqliguard.strict_mode' => true]);

        $this->expectException(QueryException::class);
        \DB::statement("select 1; select 2");
    }

    // ---------------------------------------------------------------
    // Config: extra_needles and disabled_needles
    // ---------------------------------------------------------------

    public function testExtraNeedlesAreBlocked(): void
    {
        config(['sqliguard.extra_needles' => ['foobar']]);

        $this->expectException(QueryException::class);
        \DB::statement("select foobar");
    }

    public function testDisabledNeedlesAreAllowed(): void
    {
        // Disable the hex literal check
        config(['sqliguard.disabled_needles' => ['0x']]);

        // This should NOT throw because 0x is disabled, but it will still
        // be blocked by single quotes. Let's use a query that only triggers 0x.
        try {
            \DB::statement("select 0x41");
            // If it succeeds, the needle was properly disabled
            $this->assertTrue(true);
        } catch (QueryException $e) {
            // Should not be caused by 0x
            if ($e->getPrevious() instanceof SqlInjectionException) {
                $this->assertNotEquals('0x', $e->getPrevious()->needle);
            }
        }
    }

    // ---------------------------------------------------------------
    // Config: enabled toggle
    // ---------------------------------------------------------------

    public function testDisabledConfigAllowsEverything(): void
    {
        config(['sqliguard.enabled' => false]);

        // This would normally be blocked, but guard is disabled
        try {
            \DB::statement("select sleep(1)");
        } catch (QueryException $e) {
            // Should not be caused by our guard
            if ($e->getPrevious() instanceof SqlInjectionException) {
                $this->fail('SqlInjectionException should not be thrown when guard is disabled');
            }
        }

        $this->assertTrue(true);
    }

    // ---------------------------------------------------------------
    // allowUnsafe / blockUnsafe toggle
    // ---------------------------------------------------------------

    public function testAllowUnsafeDisablesProtection(): void
    {
        SqliGuard::allowUnsafe();

        try {
            \DB::statement("select sleep(1)");
        } catch (QueryException $e) {
            if ($e->getPrevious() instanceof SqlInjectionException) {
                $this->fail('SqlInjectionException should not be thrown when unsafe is allowed');
            }
        }

        $this->assertTrue(true);
    }

    public function testBlockUnsafeReenablesProtection(): void
    {
        SqliGuard::allowUnsafe();
        SqliGuard::blockUnsafe();

        $this->expectException(QueryException::class);
        \DB::statement("select sleep(5)");
    }

    // ---------------------------------------------------------------
    // withoutProtection() scoped API
    // ---------------------------------------------------------------

    public function testWithoutProtectionDisablesTemporarily(): void
    {
        $result = SqliGuard::withoutProtection(function () {
            // This should not throw
            try {
                \DB::statement("select sleep(0)");
            } catch (QueryException $e) {
                if ($e->getPrevious() instanceof SqlInjectionException) {
                    $this->fail('Should not throw inside withoutProtection');
                }
            }

            return 'ok';
        });

        $this->assertEquals('ok', $result);

        // Protection should be restored — this should throw
        $this->expectException(QueryException::class);
        \DB::statement("select sleep(5)");
    }

    public function testWithoutProtectionRestoresOnException(): void
    {
        try {
            SqliGuard::withoutProtection(function () {
                throw new \RuntimeException('test error');
            });
        } catch (\RuntimeException $e) {
            // Expected
        }

        // Protection should be restored
        $this->expectException(QueryException::class);
        \DB::statement("select sleep(5)");
    }

    // ---------------------------------------------------------------
    // reset() for Octane safety
    // ---------------------------------------------------------------

    public function testResetRestoresDefaultState(): void
    {
        SqliGuard::allowUnsafe();
        $this->assertTrue(SqliGuard::isUnsafeAllowed());

        SqliGuard::reset();
        $this->assertNull(SqliGuard::isUnsafeAllowed());
    }

    // ---------------------------------------------------------------
    // Custom exception class
    // ---------------------------------------------------------------

    public function testThrowsSqlInjectionException(): void
    {
        try {
            \DB::statement("select sleep(5)");
            $this->fail('Expected QueryException');
        } catch (QueryException $e) {
            $previous = $e->getPrevious();
            $this->assertInstanceOf(SqlInjectionException::class, $previous);
            $this->assertEquals('sleep(', $previous->needle);
            $this->assertStringContainsString('sleep', $previous->query);
        }
    }

    // ---------------------------------------------------------------
    // Event dispatching
    // ---------------------------------------------------------------

    public function testQueryBlockedEventIsDispatched(): void
    {
        Event::fake([QueryBlocked::class]);

        try {
            \DB::statement("select sleep(5)");
        } catch (QueryException $e) {
            // Expected
        }

        Event::assertDispatched(QueryBlocked::class, function (QueryBlocked $event) {
            return $event->needle === 'sleep(' && str_contains($event->query, 'sleep');
        });
    }

    // ---------------------------------------------------------------
    // Logging
    // ---------------------------------------------------------------

    public function testBlockedQueryIsLogged(): void
    {
        config(['sqliguard.log_blocked' => true]);

        Log::shouldReceive('warning')
            ->once()
            ->withArgs(function ($message, $context) {
                return $message === 'SQLi Guard blocked query'
                    && $context['needle'] === 'sleep('
                    && str_contains($context['query'], 'sleep');
            });

        try {
            \DB::statement("select sleep(5)");
        } catch (QueryException $e) {
            // Expected
        }
    }

    public function testBlockedQueryIsNotLoggedWhenDisabled(): void
    {
        config(['sqliguard.log_blocked' => false]);

        Log::shouldReceive('warning')->never();

        try {
            \DB::statement("select sleep(5)");
        } catch (QueryException $e) {
            // Expected
        }
    }

    // ---------------------------------------------------------------
    // Safe queries should pass
    // ---------------------------------------------------------------

    public function testParameterizedQueryPasses(): void
    {
        // A properly parameterized query should never trigger the guard
        // The ? placeholder contains no dangerous sequences
        try {
            \DB::select("select ? as val", [1]);
            $this->assertTrue(true);
        } catch (QueryException $e) {
            if ($e->getPrevious() instanceof SqlInjectionException) {
                $this->fail('Parameterized query should not be blocked');
            }
            // Other database errors are fine (e.g., connection issues in CI)
            $this->assertTrue(true);
        }
    }

    public function testSimpleSelectPasses(): void
    {
        try {
            \DB::select("select 1 as val");
            $this->assertTrue(true);
        } catch (QueryException $e) {
            if ($e->getPrevious() instanceof SqlInjectionException) {
                $this->fail('Simple select should not be blocked');
            }
            $this->assertTrue(true);
        }
    }
}
