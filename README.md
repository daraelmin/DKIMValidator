# PHP DKIM Validator

A validation class for checking DKIM signatures and header settings. Requires PHP 7.3 or later.

![Test status](https://github.com/PHPMailer/DKIMValidator/workflows/Tests/badge.svg)
![Psalm coverage](https://shepherd.dev/github/vimeo/psalm/coverage.svg?)

DKIM signed email is defined in [RFC6376](https://tools.ietf.org/html/rfc6376), and provides a way to authenticate both the origin of a message, and that it has not been tampered with in transit, using cryptographic signatures. 

Looking to *send* DKIM-signed email? Check out [PHPMailer](https://github.com/PHPMailer/PHPMailer)!

## Installation

```
composer require phpmailer/dkimvalidator
```

## Usage

```php
use PHPMailer\DKIMValidator\Message;
use PHPMailer\DKIMValidator\Validator;
require 'vendor/autoload.php';
//Put a whole raw email message in here
//Load the message directly from disk -
//don't copy & paste it as that will likely affect line breaks & charsets
$message  = file_get_contents('message.eml');
//Short way, provides a simple true/false response, doesn't throw exceptions
if (Validator::isValid($message)) {
    echo "Cool, it's valid";
} else {
    echo 'Uh oh, dodgy email!';
}

//Long way, provides a detailed analysis of what is right and wrong in the DKIM signature
$validator = new Validator(new Message($message));
$analysis = $validator->validate();
$valid = $analysis->isValid();
var_dump($analysis->getResults());
```

DKIM has its flaws, not least that it's quite complex and a little fragile, as discussed in [this article](https://noxxi.de/research/breaking-dkim-on-purpose-and-by-chance.html). Overall, DKIM provides the best way we have of being able to ensure the authenticity and integrity of unencrypted email messages.

# Changelog

* Original package [angrychimp/php-dkim](https://github.com/angrychimp/php-dkim);
* Forked by [teon/dkimvalidator](https://github.com/teonsystems/php-dkim).
* Forked into [phpmailer/dkimvalidator](https://github.com/PHPMailer/DKIMValidator) by Marcus Bointon (Synchro) in October 2019:
  * Complete rewrite
  * Test suite using pest
  * Cleanup for PSR-12 and PHP 7.3.
  * Strict standards & types enforced with phpcs, phpstan, psalm.
  * CI via GitHub actions.
  * More comprehensive analysis of DKIM elements.
  * Lots of bug fixes.
