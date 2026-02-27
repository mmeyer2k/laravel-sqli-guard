# laravel-sqli-guard

A Laravel plugin that forces usage of PDO parameterization and strongly protects against SQL injection attacks.

This package should not be used as a replacement for writing secure queries! [See Caveats](#caveats).

## Install

```bash
composer require mmeyer2k/laravel-sqli-guard
```

The service provider is auto-discovered. No manual registration needed.

## Configuration

Publish the config file to customize behavior:

```bash
php artisan vendor:publish --tag=sqliguard-config
```

This creates `config/sqliguard.php` with the following options:

| Option | Default | Description |
|---|---|---|
| `enabled` | `true` | Master switch to enable/disable the guard |
| `log_blocked` | `true` | Log blocked queries at warning level |
| `strict_mode` | `false` | Enable additional patterns (`char(`, `;`) that may cause false positives |
| `extra_needles` | `[]` | Additional patterns to block (strings or regex) |
| `disabled_needles` | `[]` | Built-in patterns to skip if they cause false positives |

All options can be set via environment variables:

```env
SQLIGUARD_ENABLED=true
SQLIGUARD_LOG=true
SQLIGUARD_STRICT=false
```

## Usage

This plugin works by checking query strings for unsafe character sequences during the query preparation phase.

The query below will throw an `Illuminate\Database\QueryException` (caused by `SqlInjectionException`) due to the presence of the single quotation mark character in the query string.

```php
DB::select("select * from users where id = '$unsafe'");
```

To make this query safe and avoid an exception, use parameterized queries:

```php
DB::select("select * from users where id = ?", [$unsafe]);
```

## Overriding Protection

### Scoped (recommended)

Use `withoutProtection()` to temporarily disable the guard. Protection is always restored, even if an exception occurs:

```php
use Mmeyer2k\LaravelSqliGuard\SqliGuard;

$result = SqliGuard::withoutProtection(function () {
    return DB::select("select version()");
});
```

### Manual

```php
use Mmeyer2k\LaravelSqliGuard\SqliGuard;

SqliGuard::allowUnsafe();
// Execute queries that would normally be blocked
SqliGuard::blockUnsafe();
```

**Warning:** If an exception is thrown between `allowUnsafe()` and `blockUnsafe()`, protection remains disabled for the rest of the request. Prefer `withoutProtection()` instead.

## Forbidden Character Sequences

### Default patterns (always active)

| Pattern | Reason |
|---|---|
| `'` | The single quotation mark is the most fundamental SQL injection vector. |
| `"` | Double quotes can also enable injection in certain contexts. |
| `0x` | Hexadecimal literals are used to bypass WAFs looking for quoted sequences. |
| `--`, `#`, `/*`, `*/` | Comments can manipulate query logic. Use raw PDO parameters for binary values. |
| `@@` | System variable access (`@@version`, `@@datadir`) used for enumeration. |
| `sleep(` | Blind timing attacks and connection exhaustion DDoS. |
| `benchmark(` | Timing attacks and CPU exhaustion DDoS. |
| `version(` | Database version probing to refine attacks. |
| `load_file(` | Read arbitrary files from the server filesystem. |
| `into outfile` / `into dumpfile` | Write files to the server (webshell deployment). |
| `extractvalue(` | XML error-based blind injection in MySQL. |
| `updatexml(` | XML error-based blind injection in MySQL. |
| `/\(.*select.*information_schema.*information_schema.*\)/` | Blocks DDoS via compound `information_schema` subqueries. |

### Strict mode patterns (opt-in)

Enable with `SQLIGUARD_STRICT=true` or `'strict_mode' => true` in config.

| Pattern | Reason |
|---|---|
| `char(` | Construct strings from character codes to bypass quote filtering. |
| `;` | Stacked queries / second-order injection. |

## Events & Logging

### Logging

When `log_blocked` is enabled, blocked queries are logged at the `warning` level with the matched needle and full query string.

### Events

A `Mmeyer2k\LaravelSqliGuard\Events\QueryBlocked` event is dispatched whenever a query is blocked. Listen for it to integrate with your alerting:

```php
use Mmeyer2k\LaravelSqliGuard\Events\QueryBlocked;

Event::listen(QueryBlocked::class, function (QueryBlocked $event) {
    // $event->needle — the pattern that matched
    // $event->query  — the full query string
    // Send to Slack, PagerDuty, etc.
});
```

### Exception handling

Blocked queries throw `Mmeyer2k\LaravelSqliGuard\SqlInjectionException` (wrapped in Laravel's `QueryException`). You can catch it specifically:

```php
use Mmeyer2k\LaravelSqliGuard\SqlInjectionException;

try {
    DB::select($query);
} catch (\Illuminate\Database\QueryException $e) {
    if ($e->getPrevious() instanceof SqlInjectionException) {
        // Handle SQL injection attempt
    }
}
```

## Laravel Octane Support

The guard automatically resets its state between Octane requests, preventing state leakage across long-lived workers. No additional configuration is needed.

## Query Normalization

Queries are normalized before inspection to prevent evasion:

- Null bytes are stripped (`\0`)
- Converted to lowercase
- Whitespace is collapsed
- Spaces before parentheses are removed

## Caveats

Unfortunately, not all SQL injection scenarios can be blocked by this inspection.

Queries that blindly accept user input can still be manipulated to subvert your application, leak data, or cause denial of service.

A query that returns data can be manipulated to leak records.
Consider this poorly written hypothetical API controller route:

```php
function users()
{
    $id = request('id');

    return json_encode(DB::select("select * from users where id = $id"));
}
```

If the query string `?id=1 or id > 1` is given, all records will be returned.
Depending on the context, this could be a major security issue.

Another concern is that some DDoS attacks are possible if the attacker knows, or can guess, information about the data schema.
Again using the above function as an example, but now the query string `id= (SELECT COUNT(*) FROM users A, users B, users C, ...)` is sent.
CPU exhaustion can occur if there are many rows in the specified table(s), or if the number of junctions is high.
A similar attack is possible against `information_schema`, but it requires **no knowledge**.

## Requirements

- PHP 8.1+
- Laravel 9.x, 10.x, 11.x, or 12.x
