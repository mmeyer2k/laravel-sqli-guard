# laravel-sqli-reject
A Laravel plugin that forces usage of PDO parameterization and strongly protects against SQL injection attacks.

## Install
```bash
composer require mmeyer2k/laravel-sqli-guard
```

## Configuration
By default, this package's service provider is autoloaded

## Usage
This plugin works by checking query strings for unsafe character sequences during the query preparation process.

The query below will throw an `Illuminate\Database\QueryException` due to the presence of the single quotation mark character in the query string.
```php
DB::select("select * from users where id = '$unsafe'");
```

To make this query safe and avoid an exception, you must write the query as such:
```php
DB::select("select * from users where id = ?", [$unsafe]);
```

## Overriding Protection
To disable protection use the provided `allowUnsafe` function.
Be careful, queries could be vulnerable anywhere down-stream of this command!
```php
\Mmeyer2k\LaravelSqliGuard::allowUnsafe();
```

To re-enable protection after executing a dangerous query use `blockUnsafe`.
```php
\Mmeyer2k\LaravelSqliGuard::blockUnsafe();
```

## Forbidden Character Sequences
| Character | Reason |
|---|---|
| `'` | The single quotation has been the nemises of sql since time immemoral. |
| `"` | Some dirty tricks are also possible with double quotes. |
| `0x` | Hexidecimal conversion is often a used as a way of bypassing naive WAFs that are looking for single quoted sequences. |
| `--` and `#` | Comments can often be used to manipulate queries in clever ways. |
| `version()`| Prevents probing SQL for its version information, which can be used to refine attacks. |
| `benchmark(` | Used in SQLi timing attacks and as a DDoS vector due to its intense CPU usage. |
| `sleep(` | Used in blind timing attacks to leak information and can also be used as a connection exhaustion DDoS vector. |