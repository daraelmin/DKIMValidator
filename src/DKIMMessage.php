<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

/**
 * A decorator to add DKIM features to a regular message.
 *
 * Class DKIMMessage
 * @package PHPMailer\DKIMValidator
 */
class DKIMMessage
{
    private Message $message;

    public function __construct(Message $message)
    {
        $this->message = $message;
    }

    /**
     * @return Message
     */
    public function getMessage(): Message
    {
        return $this->message;
    }

    /**
     * Get all DKIM signature headers.
     *
     * @return array<int,DKIMHeader>
     * @throws HeaderException
     */
    public function getDKIMSignatures(): array
    {
        $matchedHeaders = [];
        foreach ($this->message->getHeaders() as $header) {
            $dkimHeader = new DKIMHeader($header);
            if ($dkimHeader->isDKIMSignature()) {
                $matchedHeaders[] = $dkimHeader;
            }
        }

        return $matchedHeaders;
    }
}
