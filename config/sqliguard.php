<?php

return [

    /*
    |--------------------------------------------------------------------------
    | Enable SQL Injection Guard
    |--------------------------------------------------------------------------
    |
    | Master switch to enable or disable the SQL injection guard. When disabled,
    | no queries will be inspected. Useful for toggling via environment variable.
    |
    */
    'enabled' => env('SQLIGUARD_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Log Blocked Queries
    |--------------------------------------------------------------------------
    |
    | When enabled, blocked queries will be logged at the warning level. This
    | is useful for security monitoring and incident response.
    |
    */
    'log_blocked' => env('SQLIGUARD_LOG', true),

    /*
    |--------------------------------------------------------------------------
    | Strict Mode
    |--------------------------------------------------------------------------
    |
    | Enables additional patterns that provide stronger protection but have a
    | higher chance of false positives. This adds checks for: char(, ;
    |
    */
    'strict_mode' => env('SQLIGUARD_STRICT', false),

    /*
    |--------------------------------------------------------------------------
    | Extra Needles
    |--------------------------------------------------------------------------
    |
    | Additional patterns to block. These are checked alongside the built-in
    | patterns. Supports both plain strings and regex patterns (delimited by /).
    |
    */
    'extra_needles' => [],

    /*
    |--------------------------------------------------------------------------
    | Disabled Needles
    |--------------------------------------------------------------------------
    |
    | Built-in patterns to skip. If a default pattern causes false positives
    | in your application, you can disable it here by adding the exact string.
    |
    */
    'disabled_needles' => [],

];
