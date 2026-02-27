<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard;

use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Log;
use Illuminate\Database\Events\StatementPrepared;
use Illuminate\Support\ServiceProvider as SP;
use Mmeyer2k\LaravelSqliGuard\Events\QueryBlocked;

class ServiceProvider extends SP
{
    /**
     * Default patterns that should never appear in parameterized query strings.
     */
    private const NEEDLES = [
        // Quotes — the most fundamental SQLi vector
        "'",
        '"',

        // Hex literals — bypass WAF detection
        '0x',

        // Comments — manipulate query logic
        '--',
        '#',
        '/*',
        '*/',

        // System variable access — enumeration
        '@@',

        // Dangerous functions — timing attacks, blind injection, DDoS
        'sleep(',
        'benchmark(',
        'version(',

        // File system access
        'load_file(',
        'into outfile',
        'into dumpfile',

        // XML error-based blind injection (MySQL)
        'extractvalue(',
        'updatexml(',

        // Compound information_schema DDoS
        '/\(.*select.*information_schema.*information_schema.*\)/',
    ];

    /**
     * Additional patterns enabled only in strict mode.
     */
    private const STRICT_NEEDLES = [
        // Char-code string construction to bypass quote filtering
        'char(',

        // Stacked queries
        ';',
    ];

    public function boot(): void
    {
        $this->publishes([
            __DIR__ . '/../config/sqliguard.php' => config_path('sqliguard.php'),
        ], 'sqliguard-config');

        $this->mergeConfigFrom(__DIR__ . '/../config/sqliguard.php', 'sqliguard');

        // Reset state between Octane requests
        if (class_exists(\Laravel\Octane\Events\RequestReceived::class)) {
            Event::listen(\Laravel\Octane\Events\RequestReceived::class, function () {
                SqliGuard::reset();
            });
        }

        Event::listen(StatementPrepared::class, function (StatementPrepared $event) {
            // Master switch from config
            if (!config('sqliguard.enabled', true)) {
                return;
            }

            // Get the runtime toggle
            $allowUnsafe = SqliGuard::isUnsafeAllowed();

            // If running from console with default state, skip checks
            if (app()->runningInConsole() && $allowUnsafe === null) {
                return;
            }

            // If explicitly allowed, skip checks
            if ($allowUnsafe === true) {
                return;
            }

            $query = self::normalize($event->statement->queryString ?? '');

            $needles = self::buildNeedleList();

            foreach ($needles as $needle) {
                $isRegex = str_starts_with($needle, '/') && str_ends_with($needle, '/');

                if ($isRegex) {
                    $matched = (bool) preg_match($needle, $query);
                } else {
                    $matched = str_contains($query, $needle);
                }

                if ($matched) {
                    if (config('sqliguard.log_blocked', true)) {
                        Log::warning('SQLi Guard blocked query', [
                            'needle' => $needle,
                            'query' => $event->statement->queryString,
                        ]);
                    }

                    QueryBlocked::dispatch($needle, $event->statement->queryString ?? '');

                    throw new SqlInjectionException($needle, $event->statement->queryString ?? '');
                }
            }
        });
    }

    /**
     * Build the full list of needles from defaults + config.
     *
     * @return string[]
     */
    private static function buildNeedleList(): array
    {
        $needles = self::NEEDLES;

        if (config('sqliguard.strict_mode', false)) {
            $needles = array_merge($needles, self::STRICT_NEEDLES);
        }

        $extra = config('sqliguard.extra_needles', []);
        if (!empty($extra)) {
            $needles = array_merge($needles, $extra);
        }

        $disabled = config('sqliguard.disabled_needles', []);
        if (!empty($disabled)) {
            $needles = array_diff($needles, $disabled);
        }

        return array_values($needles);
    }

    /**
     * Normalize a query string to prevent evasion techniques.
     */
    private static function normalize(string $sql): string
    {
        // Strip null bytes — classic WAF bypass
        $sql = str_replace("\0", '', $sql);

        // Case-insensitive matching
        $sql = strtolower($sql);

        // Normalize whitespace
        $sql = preg_replace('/\s+/', ' ', $sql);

        // Remove space before parentheses
        return str_replace(' (', '(', $sql);
    }
}
