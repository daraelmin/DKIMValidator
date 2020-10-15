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

    /**
     * Generate nice text-based output.
     *
     * @return string
     */
    public function __toString()
    {
        $out = "DKIM validation results\n";
        $out .= "Overall status: " . ($this->isValid() ? 'pass' : 'fail') . "\n";
        $signatureNumber = 1;
        foreach ($this->results as $result) {
            $out .= "Signature #" . $signatureNumber . "\n";
            $out .= "Domain and selector: " . $result->getDomain() . '/' . $result->getSelector() . "\n";
            $out .= "Validation result: " . ($result->isValid() ? 'pass' : 'fail') . "\n";
            if (count($result->getFails()) > 0) {
                $out .= "Validation failures:\n";
                foreach ($result->getFails() as $fail) {
                    $out .= $fail . "\n";
                }
            }
            if (count($result->getWarnings()) > 0) {
                $out .= "Validation warnings:\n";
                foreach ($result->getWarnings() as $warning) {
                    $out .= $warning . "\n";
                }
            }
            if (count($result->getFails()) > 0) {
                $out .= "Validation passes:\n";
                foreach ($result->getPasses() as $pass) {
                    $out .= $pass . "\n";
                }
            }
            ++$signatureNumber;
        }
        return $out;
    }

    /**
     * Generate JSON output.
     *
     * @return string
     */
    public function asJSON()
    {
        $out = [];
        $out['valid'] = $this->isValid();
        $out['signatures'] = [];
        foreach ($this->results as $result) {
            $resultSet = [];
            $resultSet['valid'] = $result->isValid();
            $resultSet['domain'] = $result->getDomain();
            $resultSet['selector'] = $result->getSelector();
            $resultSet['failures'] = [];
            if (count($result->getFails()) > 0) {
                foreach ($result->getFails() as $fail) {
                    $resultSet['failures'][] = $fail;
                }
            }
            $resultSet['warnings'] = [];
            if (count($result->getWarnings()) > 0) {
                foreach ($result->getWarnings() as $warning) {
                    $resultSet['warnings'][] = $warning;
                }
            }
            $resultSet['passes'] = [];
            if (count($result->getFails()) > 0) {
                foreach ($result->getPasses() as $pass) {
                    $resultSet['passes'][] = $pass;
                }
            }
            $out['signatures'][] = $resultSet;
        }

        return json_encode($out, JSON_PRETTY_PRINT);
    }
}
