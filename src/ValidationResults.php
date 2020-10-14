<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

/**
 * Class ValidationResults. A container holding the results of validating one or more signatures,
 * and an overall valid/invalid status.
 * @package PHPMailer\DKIMValidator
 */
final class ValidationResults
{
    /**
     * @var bool Whether the message has passed DKIM validation overall
     */
    protected $valid = false;

    /**
     * @var ValidationResult[] One result for each DKIM signature in a message
     */
    protected $results = [];

    /**
     * Add the results of validation of a single signature.
     *
     * @param ValidationResult $validationResult
     */
    public function addResult(ValidationResult $validationResult): void
    {
        if ($validationResult->isValid()) {
            //DKIM is considered as passing if *any* signature validates
            $this->valid = true;
        }
        $this->results[] = $validationResult;
    }

    /**
     * Get the list of validation results for this message.
     *
     * @return ValidationResult[]
     */
    public function getResults(): array
    {
        return $this->results;
    }

    /**
     * Has this message passed DKIM validation overall?
     * Will also return false if no results have been added.
     *
     * @return bool
     */
    public function isValid(): bool
    {
        return $this->valid;
    }
}
