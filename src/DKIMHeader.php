<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

/**
 * A decorator to add DKIM features to a regular header.
 *
 * Class DKIMHeader
 * @package PHPMailer\DKIMValidator
 */
class DKIMHeader
{
    private Header $header;

    public function __construct(Header $header)
    {
        $this->header = $header;
    }

    public function getHeader(): Header
    {
        return $this->header;
    }

    /**
     * Return a whole header canonicalized according to the `relaxed` scheme.
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4.2
     *
     * @return string
     */
    public function getRelaxedCanonicalizedHeader(): string
    {
        //Lowercase and trim header label
        $label = trim($this->header->getLowerLabel());

        //Unfold, collapse whitespace to a single space, and trim
        $value = trim((string)preg_replace('/\s+/', Header::WSP, $this->header->getValue()), " \r\n\t");

        //Stick it back together including a trailing break, note no space before or after the `:`
        return "${label}:${value}" . Header::CRLF;
    }

    /**
     * Return a whole header canonicalized according to the `simple` scheme.
     * This involves doing nothing at all!
     *
     * @see https://tools.ietf.org/html/rfc6376#section-3.4.1
     *
     * @return string
     */
    public function getSimpleCanonicalizedHeader(): string
    {
        return $this->header->getRaw();
    }

    /**
     * Is this header a DKIM signature?
     *
     * @return bool
     */
    public function isDKIMSignature(): bool
    {
        //If you want to support other DKIM implementations, override this method and add them like this
        // return in_array($this->getLowerLabel(), ['dkim-signature', 'x-google-dkim-signature'])
        return $this->header->getLowerLabel() === 'dkim-signature';
    }

    /**
     * Remove the `b` tag's value from a DKIM signature.
     * Needed when calculating signature of a set of headers.
     *
     * @param string $header
     *
     * @return string The raw header without the b value
     */
    public static function removeBValue(string $header): string
    {
        //This replacement strips trailing line breaks, so need to put it back afterwards
        return preg_replace(
            '/\bb=([^;]*)/',
            'b=',
            $header
        ) . Header::CRLF;
    }
}
