<?php

namespace Tokenly\HmacAuth;

use Exception;
use Symfony\Component\HttpFoundation\Request;

/*
* Generator
*/
class Generator
{

    protected $auth_header_namespace = 'TOKENLY';

    public function __construct($auth_header_namespace=null) {
        if (isset($auth_header_namespace)) {
            $this->auth_header_namespace = $auth_header_namespace;
        }
    }

    public function addSignatureToGuzzleRequest(\GuzzleHttp\Message\Request $request, $api_token, $secret) {
        $method = $request->getMethod();
        
        // build URL without parameters
        $url = $this->buildURL($request->getScheme(), $request->getHost(), $request->getPort()).$request->getPath();

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

    public function addSignatureToSymfonyRequest(\Symfony\Component\HttpFoundation\Request $request, $api_token, $secret) {
        $method = $request->getMethod();
        
        // build URL without parameters
        $url = $this->buildURL($request->getScheme(), $request->getHost(), $request->getPort()).$request->getPathInfo();

        // get parameters
        if ($method == 'POST') {
            $parameters = $request->request->all();
        } else {
            $parameters = $request->query->all();
        }

        // get signature
        $signature_info = $this->createSignatureParameters($method, $url, $parameters, $api_token, $secret);

        // add http headers
        $request->headers->set('X-'.$this->auth_header_namespace.'-AUTH-API-TOKEN', $api_token);
        $request->headers->set('X-'.$this->auth_header_namespace.'-AUTH-NONCE', $signature_info['nonce']);
        $request->headers->set('X-'.$this->auth_header_namespace.'-AUTH-SIGNATURE', $signature_info['signature']);

        return;
    }

    protected function buildURL($scheme, $host, $port) {
        $url = $scheme.'://'.$host;

        if (('http' == $scheme AND $port == 80) OR ('https' == $scheme AND $port == 443)) {
            return $url;
        }

        return $url.':'.$port;
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
