<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard;

use Exception;
use Illuminate\Support\Facades\Event;
use Illuminate\Database\Events\StatementPrepared;
use Illuminate\Support\ServiceProvider as SP;

class ServiceProvider extends SP
{
    private const needles = [
        'information_schema',
        'benchmark(',
        'version(',
        'sleep(',
        '--',
        '0x',
        '#',
        "'",
        '"',
        '/',
    ];

    /**
     * Bootstrap services.
     *
     * @return void
     * @throws \Mmeyer2k\LaravelSqliGuard\DangerousQueryException
     */
    public function boot()
    {
        Event::listen(StatementPrepared::class, function (StatementPrepared $event) {
            // Get the switch variable
            $allowUnsafe = SqliProtection::isUnsafeAllowed();

            // If being run from commandline, we are always safe, therefore no need to check
            // but still allow for the possibility to test by setting the allowUnsafe flag
            if (app()->runningInConsole() && $allowUnsafe === null) {
                return;
            }

            // If allowUnsafe has been called then return before checking
            if ($allowUnsafe === true) {
                return;
            }

            // Normalize query string to prevent tomfoolery
            $query = self::normalize($event->statement->queryString ?? '');

            // If query is suspicious, throw exception back to PDO which will become Illuminate\Database\QueryException
            foreach (self::needles as $needle) {
                if (str_contains($query, $needle)) {
                    throw new Exception('Query contains an invalid character sequence');
                }
            }
        });
    }

    private static function normalize(string $sql): string
    {
        $sql = strtolower($sql);

        $sql = preg_replace('/\s+/', ' ', $sql);

        $sql = str_replace(' (', '(', $sql);

        return $sql;
    }
}
