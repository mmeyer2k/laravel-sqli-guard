<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard;

use Exception;
use Illuminate\Support\Facades\Event;
use Illuminate\Database\Events\StatementPrepared;
use Illuminate\Support\ServiceProvider as SP;

class ServiceProvider extends SP
{
    private const needles = [
        'benchmark(',
        'version(',
        'sleep(',
        '--',
        '0x',
        '#',
        '/*',
        '*/',
        "'",
        '"',
        '/\(.*select.*information_schema.*information_schema.*\)/',
    ];

    /**
     * Bootstrap services.
     *
     * @return void
     * @throws Exception
     */
    public function boot()
    {
        Event::listen(StatementPrepared::class, function (StatementPrepared $event) {
            // Get the switch variable
            $allowUnsafe = SqliGuard::isUnsafeAllowed();

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

            // Define the exception to be thrown in the event of a failed query check.
            // If query is suspicious, this exception will be caught by laravel and re-thrown as Illuminate\Database\QueryException
            $error = new Exception('Query contains dangerous character sequence');

            foreach (self::needles as $needle) {
                if (substr($query, 0, 1) === '/' && substr($query, -1) === '/') {
                    // Handle regex patterns
                    if (preg_match($needle, $query)) {
                        throw $error;
                    }
                } else {
                    // Handle plain strings
                    if (strpos($query, $needle) !== false) {
                        throw $error;
                    }
                }
            }
        });
    }

    private static function normalize(string $sql): string
    {
        $sql = strtolower($sql);

        $sql = preg_replace('/\s+/', ' ', $sql);

        return str_replace(' (', '(', $sql);
    }
}
