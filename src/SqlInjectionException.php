<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard;

use RuntimeException;

class SqlInjectionException extends RuntimeException
{
    public string $needle;
    public string $query;

    public function __construct(string $needle, string $query)
    {
        $this->needle = $needle;
        $this->query = $query;

        parent::__construct("Query blocked: contains forbidden sequence '$needle'");
    }
}
