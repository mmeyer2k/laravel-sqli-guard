<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard;

class SqliGuard
{
    /**
     * Request-scoped state to avoid leakage between Octane requests.
     * null = default (console bypass applies), true = disabled, false = enabled
     */
    private static ?bool $allowUnsafe = null;

    public static function isUnsafeAllowed(): ?bool
    {
        return self::$allowUnsafe;
    }

    public static function allowUnsafe(): void
    {
        self::$allowUnsafe = true;
    }

    public static function blockUnsafe(): void
    {
        self::$allowUnsafe = false;
    }

    /**
     * Reset state to default. Called automatically on Octane request start.
     */
    public static function reset(): void
    {
        self::$allowUnsafe = null;
    }

    /**
     * Execute a callback with protection temporarily disabled.
     * Protection is always restored afterward, even if an exception is thrown.
     *
     * @template T
     * @param callable(): T $callback
     * @return T
     */
    public static function withoutProtection(callable $callback): mixed
    {
        $previous = self::$allowUnsafe;

        self::allowUnsafe();

        try {
            return $callback();
        } finally {
            self::$allowUnsafe = $previous;
        }
    }
}
