<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\HeaderException;
use PHPMailer\DKIMValidator\Message;

it(
    'rejects an empty message',
    function () {
        $message = new Message('');
    }
)->throws(InvalidArgumentException::class);

it(
    'rejects an incomplete message',
    function () {
        $message = new Message('test');
    }
)->throws(InvalidArgumentException::class);

it(
    'splits a message into headers and body',
    function () {
        $message = new Message("A: X\r\nB : Y\t\r\n\tZ  \r\n\r\n C \r\nD \t E\r\n\r\n\r\n");
        expect($message->getRawHeaders())->toEqual("A: X\r\nB : Y\t\r\n\tZ  \r\n");
        expect($message->getBody())->toEqual(" C \r\nD \t E\r\n\r\n\r\n");
    }
);

it(
    'parses headers correctly',
    function () {
        //Make a big messy header value to encode
        $utf8 = str_repeat('🐵👍éxçøԗႪ', 10);
        $qencoded = mb_encode_mimeheader($utf8, 'UTF-8', 'Q');
        $bencoded = mb_encode_mimeheader($utf8, 'UTF-8', 'B');
        $message = new Message(
            "A: X\r\nB : Y\t\r\n\tZ  \r\nQ1: $qencoded\r\nQ2: $bencoded\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        $headers = $message->getHeaders();
        expect($headers[0]->getRaw())->toEqual("A: X\r\n");
        expect($headers[0]->getLabel())->toEqual('A');
        expect($headers[0]->getLowerLabel())->toEqual('a');
        expect($headers[0]->getValue())->toEqual('X');
        expect($headers[1]->getRaw())->toEqual("B : Y\t\r\n\tZ  \r\n");
        expect($headers[1]->getLabel())->toEqual('B');
        expect($headers[1]->getLowerLabel())->toEqual('b');
        //Note that this gains a space before the Z due to unfolding
        expect($headers[1]->getValue())->toEqual("Y\t Z  ");
        expect($headers[2]->getRawValue())->toEqual($qencoded);
        expect($headers[2]->getValue())->toEqual($utf8);
        expect($headers[3]->getRawValue())->toEqual($bencoded);
        expect($headers[3]->getValue())->toEqual($utf8);
    }
);

it(
    'finds headers by name',
    function () {
        $message = new Message(
            "A: X\r\nB : Y\t\r\n\tZ  \r\nB:P\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        $headers = $message->getHeadersNamed('A');
        expect($headers)->toHaveCount(1);
        expect($headers[0]->getValue())->toEqual('X');
        expect($headers[0]->getLabel())->toEqual('A');
        $headers = $message->getHeadersNamed('B');
        expect($headers)->toHaveCount(2);
    }
);

it(
    'handles invalid headers correctly',
    function () {
        $message = new Message(
            "A: X\r\nB : Y\t\r\n\tZ  \r\nB:P\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        //For coverage
        $reflector = new ReflectionClass(Message::class);
        $method = $reflector->getMethod('parseHeaders');
        $method->setAccessible(true);
        $result = $method->invokeArgs($message, ['x']);
        expect($result)->tobeArray();
        expect($result)->toHaveCount(0);
    }
);

it(
    'parses invalid headers correctly',
    function () {
        $message = new Message(
            "A: X\r\nB : Y\t\r\n:C\tZ  \r\nB:P\r\n\r\n C \r\nD \t E\r\n\r\n\r\n"
        );
        $message->getHeadersNamed('A');
    }
)->throws(HeaderException::class);
