<?php

namespace Tokenly\HmacAuth;

use Exception;
use Tokenly\HmacAuth\Exception\AuthorizationException;

/*
* Validator
*/
class Validator
{

    const HMAC_TIMEOUT = 300; // 5 min


    protected $auth_header_namespace      = 'Tokenly';
    protected $api_secret_lookup_function = null;


    public function __construct($api_secret_lookup_function=null, $auth_header_namespace=null) {
        if (isset($auth_header_namespace)) {
            $this->auth_header_namespace = $auth_header_namespace;
        }

        if ($api_secret_lookup_function !== null) { $this->api_secret_lookup_function = $api_secret_lookup_function; }
    }

    public function setAPISecretLookupFunction($api_secret_lookup_function) {
        $this->api_secret_lookup_function = $api_secret_lookup_function;
    }

    public function validateFromRequest(\Symfony\Component\HttpFoundation\Request $request) {
        // get the request headers
        $nonce = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Nonce');
        $api_token = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Api-Token');
        $signature = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Signature');

        if (!$nonce) { throw new AuthorizationException("Missing nonce"); }
        if (!$api_token) { throw new AuthorizationException("Missing api_token"); }
        if (!$signature) { throw new AuthorizationException("Missing signature"); }

        // get the api_secret
        if ($this->api_secret_lookup_function AND is_callable($this->api_secret_lookup_function)) {
            $api_secret = call_user_func($this->api_secret_lookup_function, $api_token);
        } else {
            $api_secret = null;
        }
        if (!$api_secret) { throw new AuthorizationException("Invalid API Token", "Failed to find api secret for token $api_token"); }

        // build the method, url and parameters
        $method = $request->getMethod();
        $url = $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo();

        // get parameters
        if ($method == 'GET') {
            $parameters = $request->query->all();
        } else {
            $is_json = strpos($request->header('CONTENT_TYPE'), '/json');
            if ($is_json) {
                $parameters = $request->getContent();
                if (!strlen($parameters)) {
                    $parameters = '{}';
                }
            } else {
                $parameters = $request->request->all();
            }
        }
        
        // validate the signature
        $is_valid = $this->validate($method, $url, $parameters, $api_token, $nonce, $signature, $api_secret);
        return $is_valid;
    }

    public function validate($method, $url, $parameters, $api_token, $nonce, $signature, $secret)
    {
        if ($nonce < (time() - self::HMAC_TIMEOUT)) { throw new AuthorizationException("Invalid nonce parameter", "nonce was too old"); }
        if ($nonce > (time() + self::HMAC_TIMEOUT)) { throw new AuthorizationException("Invalid nonce parameter", "nonce was too far in the future"); }

        if (is_string($parameters)) {
            $params_string = $parameters;
        } else {
            $params_to_encode = (array)$parameters;
            $params_string = json_encode($params_to_encode, JSON_UNESCAPED_SLASHES | JSON_FORCE_OBJECT);
        }
        

        $data =
            $method."\n"
           .$url."\n"
           .$params_string."\n"
           .$api_token."\n"
           .$nonce;
        

        $expected_signature = base64_encode(hash_hmac('sha256', $data, $secret, true));


        $valid = ($signature === $expected_signature);
        if (!$valid) {
            throw new AuthorizationException("Invalid Authorization Signature", "signature mismatch: data=\n***\n".($data)."\n***\nactual signature=$signature");
        }

        return $valid;
    }
}
