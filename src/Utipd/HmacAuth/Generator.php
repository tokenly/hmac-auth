<?php

namespace Utipd\HmacAuth;

use Exception;

/*
* Generator
*/
class Generator
{

    protected $auth_header_namespace = 'UTIPD';

    public function __construct($auth_header_namespace=null) {
        if (isset($auth_header_namespace)) {
            $this->auth_header_namespace = $auth_header_namespace;
        }
    }

    public function addSignatureToGuzzleRequest(\GuzzleHttp\Message\Request $request, $api_token, $secret) {
        $method = $request->getMethod();
        
        // build URL without parameters
        $url = $request->getScheme().'://'.$request->getHost().$request->getPath();

        // get parameters
        $parameters = $request->getQuery()->toArray();

        // get signature
        $signature_info = $this->createSignatureParameters($method, $url, $parameters, $api_token, $secret);

        // add http headers
        $request->addHeader('X-'.$this->auth_header_namespace.'-AUTH-API-TOKEN', $api_token);
        $request->addHeader('X-'.$this->auth_header_namespace.'-AUTH-NONCE', $signature_info['nonce']);
        $request->addHeader('X-'.$this->auth_header_namespace.'-AUTH-SIGNATURE', $signature_info['signature']);

        return;
    }

    public function createSignatureParameters($method, $url, $parameters, $api_token, $secret)
    {
        $nonce = time();

        $params_string = json_encode((array)$parameters);

        $data =
            $method."\n"
           .$url."\n"
           .$params_string."\n"
           .$api_token."\n"
           .$nonce;

        $signature = base64_encode(hash_hmac('sha256', $data, $secret, true));
    
        return ['nonce' => $nonce, 'signature' => $signature];
    }
}
