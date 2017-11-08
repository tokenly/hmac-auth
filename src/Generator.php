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

    // returns the modified request
    public function addSignatureToGuzzle6Request(\GuzzleHttp\Psr7\Request $request, $api_token, $secret) {
        $method = $request->getMethod();
        
        // build URL without parameters
        $uri = $request->getUri();
        $url = $this->buildURLPrefix($uri->getScheme(), $uri->getHost(), $uri->getPort()).$uri->getPath();

        // get parameters
        if ($method == 'GET' OR $method == 'DELETE' AND $uri->getQuery()) {
            parse_str($uri->getQuery(), $parameters);

        } else {
            // assume json
            $json_string = $request->getBody();
            $parameters = strlen($json_string) ? json_decode($json_string) : [];
        }

        // get signature
        $signature_info = $this->createSignatureParameters($method, $url, $parameters, $api_token, $secret);

        // add http headers
        $request = $request->withHeader('X-'.$this->auth_header_namespace.'-AUTH-API-TOKEN', $api_token);
        $request = $request->withHeader('X-'.$this->auth_header_namespace.'-AUTH-NONCE', $signature_info['nonce']);
        $request = $request->withHeader('X-'.$this->auth_header_namespace.'-AUTH-SIGNATURE', $signature_info['signature']);

        return $request;
    }

    public function addSignatureToSymfonyRequest(\Symfony\Component\HttpFoundation\Request $request, $api_token, $secret) {
        $method = $request->getMethod();
        
        // build URL without parameters
        $url = $this->buildURLPrefix($request->getScheme(), $request->getHost(), $request->getPort()).$request->getPathInfo();

        // get parameters
        if ($method == 'GET' OR ($method == 'DELETE' && $request->query->count() > 0)) {
            $parameters = $request->query->all();
        } else {
            $is_json = strpos($request->headers->get('CONTENT_TYPE'), '/json');
            if ($is_json) {
                $parameters = json_decode($request->getContent(), true);
            } else {
                $parameters = $request->request->all();
            }
        }

        // get signature
        $signature_info = $this->createSignatureParameters($method, $url, $parameters, $api_token, $secret);

        // add http headers
        $request->headers->set('X-'.$this->auth_header_namespace.'-AUTH-API-TOKEN', $api_token);
        $request->headers->set('X-'.$this->auth_header_namespace.'-AUTH-NONCE', $signature_info['nonce']);
        $request->headers->set('X-'.$this->auth_header_namespace.'-AUTH-SIGNATURE', $signature_info['signature']);

        return $request;
    }

    public function addSignatureToHeadersArray($method, $url, $parameters, $api_token, $secret, $headers_array=[]) {
        $url_parts = parse_url($url);
        if (!isset($url_parts['scheme']) OR !isset($url_parts['host']) OR !isset($url_parts['path'])) {
            throw new Exception("Invalid URL", 1);
        }
        $port = isset($url_parts['port']) ? $url_parts['port'] : '';
        $url = $this->buildURLPrefix($url_parts['scheme'], $url_parts['host'], $port).$url_parts['path'];

        // get parameters
        if ($method == 'GET') {
            if (isset($url_parts['query']) AND strlen($url_parts['query'])) {
                // replace the parameters with the query
                parse_str($url_parts['query'], $parsed_query);
                $parameters = $parsed_query;
            }
        }

        // get signature
        $signature_info = $this->createSignatureParameters($method, $url, $parameters, $api_token, $secret);

        // add http headers
        $headers_array['X-'.$this->auth_header_namespace.'-AUTH-API-TOKEN'] = $api_token;
        $headers_array['X-'.$this->auth_header_namespace.'-AUTH-NONCE']     = $signature_info['nonce'];
        $headers_array['X-'.$this->auth_header_namespace.'-AUTH-SIGNATURE'] = $signature_info['signature'];

        return $headers_array;
    }

    // ------------------------------------------------------------------------

    protected function buildURLPrefix($scheme, $host, $port) {
        $url = $scheme.'://'.$host;

        if (('http' == $scheme AND ($port == 80 OR !$port)) OR ('https' == $scheme AND ($port == 443 OR !$port))) {
            return $url;
        }

        return $url.':'.$port;
    }

    public function createSignatureParameters($method, $url, $parameters, $api_token, $secret)
    {
        $nonce = time();

        $params_to_encode = (array)$parameters;

        if (empty($params_to_encode)) {
            $params_string = '{}';
        } else {
            $params_string = json_encode($params_to_encode, JSON_UNESCAPED_SLASHES | JSON_FORCE_OBJECT);
        }


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
