<?php

declare(strict_types=1);

use PHPMailer\DKIMValidator\DKIMHeader;
use PHPMailer\DKIMValidator\Header;
use PHPMailer\DKIMValidator\HeaderException;

/**
 * This was a real bug that appeared in OpenDKIM
 * @see https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=840015
 */

it(
    'correctly canonicalizes headers with early folds',
    function () {
        $header = new DKIMHeader(new Header(
            "Subject:\r\n    long subject text continued on subsequent lines ...\r\n"
        ));
        expect($header->getRelaxedCanonicalizedHeader())->toEqual(
            "subject:long subject text continued on subsequent lines ...\r\n"
        );
    }
);

it(
    'removes `b` tag values from canonicalized DKIM signatures correctly',
    function () {
        $header = new DKIMHeader(
            new Header(
                "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n" .
                " d=example.com; s=20161025;\r\n" .
                " h=from:content-transfer-encoding:mime-version:subject:message-id:date\r\n" .
                "  :to;\r\n" .
                " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
                " b=ksCW5/xo9hDd+sm+hwQ8UtJVoh7R6wJLH+vVI092WyE6D1uIiNSFDPx4Dl3RL3f/fC\r\n" .
                "  sVLlx5FSnUheBo/VnFM1cYnbfbDTL+FHXomU+x9pcb1aUH6dTIhjJNpGIkXaXb9PQKdW\r\n" .
                "  8fy246aQH7GGsVyENNHOFE31vJM0jziSRCCfob9xhG0Z7/3iu5mh37nY3cJqD3ZfQaoi\r\n" .
                "  nrUGAbIqEolT2QOYPVVkuSZxgNl8ijJt+PjTyNiNkNi091eoetWHYYnRAoY8OHzErcJQ\r\n" .
                "  yydzSy5cypx21c1V45oXHhAYx1mVvFQXb24CNPlBXyoJMJ+tOvYIbhqfFzYA7UEfmpPZ\r\n" .
                "  3PGg==\r\n"
            )
        );
        expect(DKIMHeader::removeBValue($header->getRelaxedCanonicalizedHeader()))->toEqual(
            "dkim-signature:v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=20161025;" .
            " h=from:content-transfer-encoding:mime-version:subject:message-id:date :to;" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=; b=\r\n"
        );
        expect(DKIMHeader::removeBValue($header->getSimpleCanonicalizedHeader()))->toEqual(
            "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;\r\n" .
            " d=example.com; s=20161025;\r\n" .
            " h=from:content-transfer-encoding:mime-version:subject:message-id:date\r\n" .
            "  :to;\r\n" .
            " bh=g3zLYH4xKxcPrHOD18z9YfpQcnk/GaJedfustWU5uGs=;\r\n" .
            " b=\r\n"
        );
    }
);
