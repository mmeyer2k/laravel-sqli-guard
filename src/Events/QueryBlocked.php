<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard\Events;

use Illuminate\Foundation\Events\Dispatchable;

class QueryBlocked
{
    use Dispatchable;

    public string $needle;
    public string $query;

    public function __construct(string $needle, string $query)
    {
        $this->needle = $needle;
        $this->query = $query;
    }
}
