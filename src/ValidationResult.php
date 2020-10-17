<?php

declare(strict_types=1);

namespace PHPMailer\DKIMValidator;

final class ValidationResult
{
    /**
     * @var bool Whether this validation has passed or not
     */
    protected $valid = true;

    /**
     * @var string[] A list of tests that passed
     */
    protected $passes = [];

    /**
     * @var string[] A list of tests that failed
     */
    protected $fails = [];

    /**
     * @var string[] A list of tests that generated warnings (non-fatal errors)
     */
    protected $warnings = [];

    /**
     * @var string The domain that this test was run for
     */
    protected $domain = '';

    /**
     * @var string The DKIM selector that was used for this validation
     */
    protected $selector = '';

    public function isValid(): bool
    {
        return $this->valid;
    }

    /**
     * @return string[]
     */
    public function getPasses(): array
    {
        return $this->passes;
    }

    /**
     * @return string[]
     */
    public function getFails(): array
    {
        return $this->fails;
    }

    /**
     * @return string[]
     */
    public function getWarnings(): array
    {
        return $this->warnings;
    }

    public function getDomain(): string
    {
        return $this->domain;
    }

    public function getSelector(): string
    {
        return $this->selector;
    }

    /**
     * Store the domain that this signature is for.
     *
     * @param string $domain
     */
    public function setDomain(string $domain): void
    {
        $this->domain = $domain;
    }

    /**
     * Store the selector used for this validation.
     *
     * @param string $selector
     */
    public function setSelector(string $selector): void
    {
        $this->selector = $selector;
    }

    /**
     * @param string $message
     */
    public function addFail(string $message): void
    {
        //If we failed a test, this validation is invalid overall
        $this->valid = false;
        $this->fails[] = $message;
    }

    /**
     * @param string $message
     */
    public function addPass(string $message): void
    {
        $this->passes[] = $message;
    }

    /**
     * @param string $message
     */
    public function addWarning(string $message): void
    {
        $this->warnings[] = $message;
    }
}
