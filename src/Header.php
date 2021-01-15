<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

/**
 * A single email message header.
 * @package PHPMailer\DKIMValidator
 */
final class Header
{
    /**
     * RFC822 line break sequence
     */
    public const CRLF = "\r\n";

    /**
     * String used when folding white space
     */
    public const FWS = ' ';

    /**
     * String used when unfolding headers
     */
    public const WSP = ' ';

    /**
     * @var string Raw original text of a header, including label, line breaks and FWS
     */
    private string $raw;

    /**
     * @var string The header label
     */
    private string $label;

    /**
     * @var string The raw
     */
    private string $value;

    /**
     * Header constructor.
     *
     * @param string $header A complete *single* header including line breaks and any FWS
     *
     * @throws HeaderException
     */
    public function __construct(string $header)
    {
        if (empty($header)) {
            throw new \InvalidArgumentException('Header is empty');
        }
        $this->raw = $header;
        //Though the trailing break belongs to the header, we don't want to process it as a line in its own right
        //so trim it before exploding
        $headerLines = explode(self::CRLF, rtrim($header, "\r\n"));
        $headerLineIndex = 0;
        $currentHeaderLabel = '';
        $currentHeaderValue = '';
        $matches = [];
        foreach ($headerLines as $headerLine) {
            if (preg_match('/^([^ \t]+?)[ \t]*(?::[ \t]*)(.*)$/', $headerLine, $matches)) {
                //This line does not start with FWS, so it's the start of a new header
                $currentHeaderLabel = $matches[1];
                $currentHeaderValue = $matches[2] . self::CRLF;
            } elseif (preg_match('/^[ \t]+(.*)$/', $headerLine, $matches)) {
                //This line starts with FWS, so it should be a folded continuation of the current header
                if ($headerLineIndex === 0) {
                    throw new HeaderException('Invalid header starting with a folded line');
                }

                $currentHeaderValue .= self::FWS . $matches[1] . self::CRLF;
            } else {
                throw new HeaderException('Encountered something weird!');
            }
            ++$headerLineIndex;
        }
        $this->label = $currentHeaderLabel;
        $this->value = rtrim($currentHeaderValue, "\r\n");
    }

    /**
     * Get the header label only.
     *
     * @return string
     */
    public function getLabel(): string
    {
        return $this->label;
    }

    /**
     * Get the header label in lower case.
     *
     * @return string
     */
    public function getLowerLabel(): string
    {
        return strtolower($this->label);
    }

    /**
     * Get the raw header value (not including the label).
     *
     * @return string
     */
    public function getRawValue(): string
    {
        return $this->value;
    }

    /**
     * Return the the header value with any RFC2047 encoding removed.
     * Note that decoding should be applied *before* unfolding
     *
     * @return string
     */
    public function getDecodedValue(): string
    {
        if (strpos($this->value, '=?') !== 0) {
            //The header does not appear to be encoded, so return raw value instead
            return $this->value;
        }

        return mb_decode_mimeheader($this->value);
    }

    /**
     * Get the value of a header, fully decoded and unfolded.
     *
     * @return string
     */
    public function getValue(): string
    {
        //Unfold header value after decoding it
        return preg_replace('/\r\n[ \t]+/', self::FWS, $this->getDecodedValue());
    }

    /**
     * Get a header value unfolded and decoded with all spaces removed.
     * Used by some special-case headers like DKIM-Signature that don't want unfolded FWS preserved
     *
     * @return string
     */
    public function getValueWithoutSpaces(): string
    {
        //Unfold header value
        return preg_replace('/[ \t]+/', '', $this->getValue());
    }

    /**
     * Get the entire untouched header, including its label and any folded lines.
     *
     * @return string
     */
    public function getRaw(): string
    {
        return $this->raw;
    }
}
