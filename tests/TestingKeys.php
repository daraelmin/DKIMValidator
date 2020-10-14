<?php

namespace PHPMailer\DKIMValidator\Tests;

final class TestingKeys
{
    private const PUBLIC_KEY_PATH = __DIR__ . '/public.key';
    private const PRIVATE_KEY_PATH = __DIR__ . '/private.key';

    /**
     * Get the public key
     *
     * @return string
     */
    public static function getPublicKey(): string
    {
        $key = file_get_contents(self::PUBLIC_KEY_PATH);
        if ($key === false) {
            return '';
        }

        return $key;
    }

    /**
     * Get the private key
     *
     * @return string
     */

    public static function getPrivateKey(): string
    {
        $key = file_get_contents(self::PRIVATE_KEY_PATH);
        if ($key === false) {
            return '';
        }
        return $key;
    }

    /**
     * Get a public key in the format expected from DNS.
     *
     * @param bool $single Whether to return a single record or broken into chunks
     *
     * @return string[]
     */
    public static function getPublicKeyInDNSFormat($single = false): array
    {
        $lines = file(self::PUBLIC_KEY_PATH);
        if ($lines === false) {
            return [''];
        }
        //Start with standard DKIM preamble (for an RSA key)
        $fullkey = 'v=DKIM1; k=rsa; p=';
        //Stick all the lines together
        foreach ($lines as $line) {
            if (strpos($line, '-----') === 0) {
                //Skip delimiter lines
                continue;
            }
            //Remove line breaks and concat
            $fullkey .= trim($line);
        }
        if ($single) {
            return [$fullkey];
        }
        //Split into pieces of up to 255 chars
        $outchunks = str_split($fullkey, 255);

        return $outchunks;
    }
}
