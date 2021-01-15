<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

use InvalidArgumentException;

final class Message
{
    /**
     * Carriage return, line feed; the standard RFC822 line break
     */
    public const CRLF = "\r\n";

    /**
     * Line feed character; standard unix line break
     */
    public const LF = "\n";

    /**
     * Carriage return character (Classic MacOS line break)
     */
    public const CR = "\r";

    /**
     * Default whitespace string
     */
    public const WSP = ' ';

    /**
     * The original, unaltered message
     *
     * @var string
     */
    private string $raw;

    /**
     * Message headers, as a string with CRLF line breaks
     *
     * @var string
     */
    private string $headers;

    /**
     * Message headers, parsed into an array or Header objects
     *
     * @var Header[]
     */
    private array $parsedHeaders = [];

    /**
     * Message body, as a string with CRLF line breaks
     *
     * @var string
     */
    private $body;

    /**
     * Constructor
     *
     * @param string $rawMessage
     */
    public function __construct(string $rawMessage = '')
    {
        //Ensure all processing uses UTF-8
        mb_internal_encoding('UTF-8');
        $this->raw = $rawMessage;
        if ($this->raw === '') {
            throw new InvalidArgumentException('No message content provided');
        }
        //Normalize line breaks to CRLF
        $message = str_replace([self::CRLF, self::CR, self::LF], [self::LF, self::LF, self::CRLF], $this->raw);
        //Split out headers and body, separated by the first double line break
        if (strpos($message, self::CRLF . self::CRLF) === false) {
            throw new InvalidArgumentException('Message content is not a valid email message');
        }
        [$headers, $body] = explode(self::CRLF . self::CRLF, $message, 2);
        //The last header retains a trailing line break, because the break is considered part of the header
        $this->headers = $headers . self::CRLF;
        $this->body = $body;
    }

    /**
     * Get the parsed headers, parsing them if we've not done so already.
     *
     * @return Header[]
     * @throws HeaderException
     */
    public function getHeaders(): array
    {
        if (count($this->parsedHeaders) === 0) {
            $this->parsedHeaders = $this->parseHeaders($this->headers);
        }

        return $this->parsedHeaders;
    }

    /**
     * Parse a complete header block.
     *
     * @param string $headers
     *
     * @return Header[]
     * @throws HeaderException
     */
    protected function parseHeaders(string $headers): array
    {
        $matches = [];
        $resultCount = preg_match_all('/(^(?:[^ \t].*[\r\n]+(?:[ \t].*[\r\n]+)*))/m', $headers, $matches);
        //Need to suppress due to a bug in psalm
        /** @psalm-suppress DocblockTypeContradiction */
        if ($resultCount === false || $resultCount === 0 || ! isset($matches[0])) {
            return [];
        }
        $parsedHeaders = [];
        /** @psalm-suppress MixedAssignment */
        foreach ($matches[0] as $match) {
            $parsedHeaders[] = new Header((string)$match);
        }

        return $parsedHeaders;
    }

    /**
     * Find message headers that match a given name.
     * May include multiple headers with the same name.
     *
     * @param string $headerName
     *
     * @return Header[]
     * @throws HeaderException
     */
    public function getHeadersNamed(string $headerName): array
    {
        $headerName = strtolower($headerName);
        $matchedHeaders = [];
        foreach ($this->getHeaders() as $header) {
            //Don't exit early as there may be multiple headers with the same name
            if ($header->getLowerLabel() === $headerName) {
                $matchedHeaders[] = $header;
            }
        }
        return $matchedHeaders;
    }

    /**
     * Return the message body.
     *
     * @return string
     */
    public function getBody(): string
    {
        return $this->body;
    }

    /**
     * Return the original message headers as a raw string.
     *
     * @return string
     */
    public function getRawHeaders(): string
    {
        return $this->headers;
    }
}
