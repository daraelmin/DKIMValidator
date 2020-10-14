<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

final class Resolver implements ResolverInterface
{
    /**
     * @param string $domain
     *
     * @return string[]
     */
    public static function getTextRecords(string $domain): array
    {
        if (!Validator::validateDomain($domain)) {
            return [];
        }
        //This automatically resolves CNAMEs for a domain if they are present
        $records = dns_get_record($domain, DNS_TXT);
        $txtRecords = [];
        if ($records !== false) {
            foreach ($records as $record) {
                //If the record was split into multiple strings, this element will contain a merged version
                if (array_key_exists('txt', $record)) {
                    $txtRecords[] = (string) $record['txt'];
                }
            }
        }

        return $txtRecords;
    }
}
