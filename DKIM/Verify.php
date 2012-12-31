<?php

/**
 * @see DKIM
 */
// require_once 'DKIM.php';



class DKIM_Verify extends DKIM {
    
    /**
     *
     *
     */
    private $_publicKeys;
    
    /**
     * Validates all present DKIM signatures
     *
     * @return array
     * @throws DKIM_Exception
     */
    public function validate() {
        
        $results = array();
        
        // find the present DKIM signatures
        $signatures = $this->_getHeaderFromRaw('DKIM-Signature');
        $signatures = $signatures['DKIM-Signature'];
        var_dump($signatures);
        
        // Validate the Signature Header Field
        $pubKeys = array();
        foreach ($signatures as $num => $signature) {
            
            $dkim = preg_replace('/\s+/s', '', $signature);
            $dkim = explode(';', trim($dkim));
            foreach ($dkim as $key => $val) {
                list($newkey, $newval) = explode('=', trim($val), 2);
                unset($dkim[$key]);
                if ($newkey == '') {
                    continue;
                }
                $dkim[$newkey] = $newval;
            }
            
            // Verify all required values are present
            // http://tools.ietf.org/html/rfc4871#section-6.1.1
            $required = array ('v', 'a', 'b', 'bh', 'd', 'h', 's');
            foreach ($required as $key) {
                if (!isset($dkim[$key])) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "signature missing required tag: $key",
                    );
                    continue;
                }
            }
            // abort if we have any errors at this point
            if (sizeof($results[$num])) {
                continue;
            }
            
            if ($dkim['v'] != 1) {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => 'incompatible version: ' . $dkim['v'],
                );
                continue;
            }
            // todo: other field validations
            
            // d is same or subdomain of i
            // permfail: domain mismatch
            // if no i, assume it is "@d"
            
            // if h does not include From,
            // permfail: From field not signed
            
            // if x exists and expired,
            // permfail: signature expired
            
            // check d= against list of configurable unacceptable domains
            
            // optionally require user controlled list of other required signed headers
            
            
            // Get the Public Key
            // (note: may retrieve more than one key)
            list($qType, $qFormat) = explode('/', $dkim['q']);
            $pubDns = array();
            $abort = false;
            switch ($qType) {
                case 'dns':
                    switch ($qFormat) {
                        case 'txt':
                            $this->_publicKeys[$dkim['d']] = self::fetchPublicKey($dkim['d'], $dkim['s']);
                            
                            break;
                        default:
                            $results[$num][] = array (
                                'status' => 'permfail',
                                'reason' => 'Public key unavailable (unknown q= query format)',
                            );
                            $abort = true;
                            continue;
                            break;
                    }
                    break;
                default:
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => 'Public key unavailable (unknown q= query format)',
                    );
                    $abort = true;
                    continue;
                    break;
            }
            if ($abort === true) {
                continue;
            }
            
            // http://tools.ietf.org/html/rfc4871#section-6.1.3
            // build/canonicalize headers
            $headerList = explode(':', $dkim['h']);
            $headersToCanonicalize = array();
            foreach ($headerList as $headerName) {
                $headersToCanonicalize = array_merge($headersToCanonicalize, $this->_getHeaderFromRaw($headerName, 'string'));
            }
            $headersToCanonicalize[] = 'DKIM-Signature: ' . preg_replace('/b=(.*)$/s', 'b=', $signature);
            
            // get canonicalization algorithm
            list($cHeaderStyle, $cBodyStyle) = explode('/', $dkim['c']);
            list($alg, $hash) = explode('-', $dkim['a']);

            // hash the headers
            $cHeaders = $this->_canonicalizeHeader($headersToCanonicalize, $cHeaderStyle);
            $hHeaders = self::_hashBody($cHeaders, $hash);
            
            // canonicalize body
            $cBody = $this->_canonicalizeBody($cBodyStyle);
            
            // Hash/encode the body
            $bh = self::_hashBody($cBody, $hash);
            
            if ($bh !== $dkim['bh']) {
                $results[$num][] = array (
                    'status' => 'permfail',
                    'reason' => "Computed body hash does not match signature body hash",
                );
            }
            
            // Iterate over keys
            foreach ($this->_publicKeys[$dkim['d']] as $num => $publicKey) {
                // Validate key
                // confirm that pubkey version matches sig version (v=)
                if ($publicKey['v'] !== 'DKIM' . $dkim['v']) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key version does not match signature version ({$dkim['d']} key #$num)",
                    );
                }
                
                // confirm that published hash matches sig hash (h=)
                if (isset($publicKey['h']) && $publicKey['h'] !== $hash) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key hash algorithm does not match signature hash algorithm ({$dkim['d']} key #$num)",
                    );
                }
                
                // confirm that the key type matches the sig key type (k=)
                if (isset($publicKey['k']) && $publicKey['k'] !== $alg) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "Public key type does not match signature key type ({$dkim['d']} key #$num)",
                    );
                }
                
                // See http://tools.ietf.org/html/rfc4871#section-3.6.1
                // verify pubkey granularity (g=)
                
                // verify service type (s=)
                
                // check testing flag
                
                
                // Compute the Verification
                $vResult = self::_signatureIsValid($publicKey['p'], $dkim['b'], $hHeaders);
                var_dump($vResult);
                if (!$vResult) {
                    $results[$num][] = array (
                        'status' => 'permfail',
                        'reason' => "signature did not verify ({$dkim['d']} key #$num)",
                    );
                } else {
                    $results[$num][] = array (
                        
                    );
                }
            }
            
        }
            
        return $results;
    }
    
    /**
     *
     *
     */
    public static function fetchPublicKey($domain, $selector) {
        $host = sprintf('%s._domainkey.%s', $selector, $domain);
        $pubDns = dns_get_record($host, DNS_TXT);
        
        if ($pubDns === false) {
            return false;
        }
        
        $public = array();
        foreach ($pubDns as $record) {
            $parts = explode(';', trim($record['txt']));
            $record = array();
            foreach ($parts as $part) {
                list($key, $val) = explode('=', trim($part), 2);
                $record[$key] = $val;
            }
            $public[] = $record;
        }
        
        return $public;
    }
    
    /**
     *
     *
     */
    protected static function _signatureIsValid($pub, $sig, $str) {
        // Convert key back into PEM format
        $key = sprintf("-----BEGIN PUBLIC KEY-----\n%s\n-----END PUBLIC KEY-----", wordwrap($pub, 64, "\n", true));
        
        // prefer Crypt_RSA
        // http://phpseclib.sourceforge.net
        if (false && class_exists('Crypt_RSA')) {
            $rsa = new Crypt_RSA();
            $rsa->loadKey(base64_decode($pub));
            return $rsa->verify(base64_decode($str), base64_decode($sig));
        } else {
            return openssl_verify(base64_decode($str), base64_decode($sig), $key);
        }
        
    }
    
}