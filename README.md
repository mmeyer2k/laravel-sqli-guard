# laravel-sqli-reject
A Laravel plugin that forces usage of PDO parameterization and strongly protects against SQL injection attacks.

This package should not be used as a replacement for writing secure queries!!! [See Caveats](#caveats).

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
| Character                                                  | Reason                                                                                                                                                             |
|------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `'`                                                        | The single quotation has been the nemises of SQL since the beginning of time.                                                                                      |
| `"`                                                        | Some dirty tricks are also possible with double quotes.                                                                                                            |
| `0x`                                                       | Hexadecimal conversion is often a used as a way of bypassing naive WAFs that are looking for single quoted sequences.                                              |
| `--`, `#`, `/*` and `*/`                                   | Comments can often be used to manipulate queries in clever ways. If binary values need to be supplied, use raw PDO string parameter.                               |
| `sleep(`                                                   | Used in blind timing attacks to leak information and can also be used as a connection exhaustion DDoS vector.                                                      |
| `version(`                                                 | Prevents probing SQL for its version information, which can be used to refine attacks.                                                                             |
| `benchmark(`                                               | Used in SQLi timing attacks and as a DDoS vector due to its intense CPU usage.                                                                                     |
| `/\(.*select.*information_schema.*information_schema.*\)/` | Prevents CPU overload DDoS attacks by blocking subqueries that compound data from `information_schema`. This rule is unlikely to ever be used in a legitimate way. |

## Caveats
Unfortunately, not all SQL injection scenarios can be blocked by this simple inspection.

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