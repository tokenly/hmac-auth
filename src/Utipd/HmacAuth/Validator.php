<?php

namespace Utipd\HmacAuth;

use Exception;
use Utipd\HmacAuth\Exception\AuthorizationException;

/*
* Validator
*/
class Validator
{

    const HMAC_TIMEOUT = 300; // 5 min


    protected $auth_header_namespace      = 'Utipd';
    protected $api_secret_lookup_function = null;


    public function __construct($api_secret_lookup_function, $auth_header_namespace=null) {
        if (isset($auth_header_namespace)) {
            $this->auth_header_namespace = $auth_header_namespace;
        }

        $this->api_secret_lookup_function = $api_secret_lookup_function;
    }

    public function buildHMacAuthBeforeFunction() {
        return function(\Symfony\Component\HttpFoundation\Request $request) {
            try {
                if ($this->validateFromRequest($request)) {
                    // validated
                    return;
                } 
                $error_message = 'Authentication Failed';
                $http_error_code = 403;

            } catch (AuthorizationException $e) {
                $error_message = $e->getAuthorizationErrorString();
                $http_error_code = $e->getCode();

            } catch (Exception $e) {
                $error_message = 'Authentication Failed';
                $http_error_code = 403;
            }

            return new Response($error_message, $http_error_code);
        };
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
        $api_secret = call_user_func($this->api_secret_lookup_function, $api_token);
        if (!$api_secret) { throw new AuthorizationException("Invalid API Token", "Failed to find api secret for token $api_token"); }

        // build the method, url and parameters
        $method = $request->getMethod();
        $url = $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo();
        $parameters = $method == 'POST' ? $request->request->all() : $request->query->all();
        
        // validate the signature
        $is_valid = $this->validate($method, $url, $parameters, $api_token, $nonce, $signature, $api_secret);
        return $is_valid;
    }

    public function validate($method, $url, $parameters, $api_token, $nonce, $signature, $secret)
    {
        if ($nonce < (time() - self::HMAC_TIMEOUT)) { throw new AuthorizationException("Invalid nonce parameter", "nonce was too old"); }
        if ($nonce > (time() + self::HMAC_TIMEOUT)) { throw new AuthorizationException("Invalid nonce parameter", "nonce was too far in the future"); }

        $params_string = json_encode((array)$parameters);

        $data =
            $method."\n"
           .$url."\n"
           .$params_string."\n"
           .$api_token."\n"
           .$nonce;

        $expected_signature = base64_encode(hash_hmac('sha256', $data, $secret, true));

        $valid = ($signature === $expected_signature);
        if (!$valid) {
            throw new AuthorizationException("Invalid Authorization Signature", "signature mismatch: data=".($data)."\nsignature=$signature");
        }

        return $valid;
    }
}
