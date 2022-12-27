<?php declare(strict_types=1);

namespace Mmeyer2k\LaravelSqliGuard;

class SqliGuard
{
    private const configString = 'sqliguard.allow_unsafe_mysql';

    public static function isUnsafeAllowed(): ?bool
    {
        return config(self::configString);
    }

    public static function allowUnsafe(): void
    {
        config([self::configString => true]);
    }

    public static function blockUnsafe(): void
    {
        config([self::configString => false]);
    }
}
