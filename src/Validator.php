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


    protected $auth_header_namespace          = 'Tokenly';
    protected $api_secret_lookup_function     = null;
    protected $signed_url_validation_function = null;


    public function __construct($api_secret_lookup_function=null, $auth_header_namespace=null) {
        if (isset($auth_header_namespace)) {
            $this->auth_header_namespace = $auth_header_namespace;
        }

        if ($api_secret_lookup_function !== null) { $this->api_secret_lookup_function = $api_secret_lookup_function; }
    }

    public function setAPISecretLookupFunction($api_secret_lookup_function) {
        $this->api_secret_lookup_function = $api_secret_lookup_function;
    }

    public function setSignedURLValidationFunction($signed_url_validation_function) {
        $this->signed_url_validation_function = $signed_url_validation_function;
    }

    public function validateFromRequest(\Symfony\Component\HttpFoundation\Request $request) {
        // get the request headers
        $nonce = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Nonce');
        $api_token = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Api-Token');
        $signature = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Signature');
        $signed_url = $request->headers->get('X-'.$this->auth_header_namespace.'-Auth-Signed-Url');

        if (!$nonce AND !$api_token AND !$signature) { throw new AuthorizationException("Missing authentication credentials"); }

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

        // mangle URL if X-TOKENLY-AUTH-SIGNED-URL was provided
        if ($signed_url) {
            if ($this->signed_url_validation_function !== null AND is_callable($this->signed_url_validation_function)) {
                $actual_url = $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo();
                $signed_url_is_valid = call_user_func($this->signed_url_validation_function, $actual_url, $signed_url);
            } else {
                $signed_url_is_valid = false;
            }
            if (!$signed_url_is_valid) { throw new AuthorizationException("Invalid Signed URL", "The URL signed for this request was not valid"); }
            $url = $signed_url;
        } else {
            $url = $request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo();
        }

        // overcome bad parameter encodings
        $parameter_sets_to_check = [];

        // get parameters
        if ($method == 'GET') {
            $parameters = $request->query->all();
            $parameter_sets_to_check[] = $parameters;
        } else if ($method == 'DELETE' AND $request->query->count() > 0) {
            // DELETE with query parameters
            $parameters = $request->query->all();
            $parameter_sets_to_check[] = $parameters;
        } else {
            $is_json = !!strpos($request->header('CONTENT_TYPE'), '/json');
            if ($is_json) {
                $parameters = $request->getContent();
                if (!strlen($parameters)) {
                    $parameters = '{}';
                    $parameter_sets_to_check[] = $parameters;
                } else {
                    $parameter_sets_to_check[] = $parameters;

                    // try re-encoding the string
                    $re_encoded_parameters = json_encode(json_decode($parameters, true), JSON_UNESCAPED_SLASHES | JSON_FORCE_OBJECT);
                    if ($re_encoded_parameters !== $parameters) {
                        $parameter_sets_to_check[] = $re_encoded_parameters;
                    }

                }

            } else {
                $parameters = $request->request->all();
                $parameter_sets_to_check[] = $parameters;
            }
        }
        
        // validate the signature
        $files = $request->files->all();
        foreach($parameter_sets_to_check as $parameter_set_to_check) {
            $is_valid = $this->validate($method, $url, $parameter_set_to_check, $files, $api_token, $nonce, $signature, $api_secret, $error_info);
            if ($is_valid) { return $is_valid; }
            if (!isset($first_error_info)) { $first_error_info = $error_info; }
        }

        // none were valid
        if ($first_error_info) { throw new AuthorizationException($first_error_info[0], $first_error_info[1]); }
        return false;
    }

    public function validate($method, $url, $parameters, $files, $api_token, $nonce, $signature, $secret, &$error_info)
    {
        $error_info = [];
        if ($nonce < (time() - self::HMAC_TIMEOUT)) { $error_info = ["Invalid nonce parameter", "nonce was too old"]; return false; }
        if ($nonce > (time() + self::HMAC_TIMEOUT)) { $error_info = ["Invalid nonce parameter", "nonce was too far in the future"]; return false; }

        $actual_file_hash = null;
        if ($files) {
            if (count($files) > 1) { $error_info = ["Multiple files found", "Found ".count($files)." files.  Expected 1"]; return false; }
            // only 1st file
            foreach ($files as $file) {
                $filepath = $file;
                break;
            }

            $actual_file_hash = null;
            if (file_exists($filepath)) {
                $actual_file_hash = hash_file('sha256', $filepath);
            }
            if (!$actual_file_hash) { $error_info = ["Unabled to calculate file hash.", "file hash not found for file $filepath"]; return false; }

            $expected_file_hash = isset($parameters['filehash']) ? $parameters['filehash'] : null;
            if (!$expected_file_hash) { $error_info = ["Unabled to find file hash.", "file hash not found in parameters for uploaded file $filepath"]; return false; }

            if ($expected_file_hash != $actual_file_hash) {
                $error_info = ["File hash mismatch.", "file hash mismatch for uploaded file $filepath.  Actual hash was $actual_file_hash.  Expected $expected_file_hash"]; return false;
            }


        }


        if (is_string($parameters)) {
            $params_string = $parameters;
            $decoded_parameters = null;
        } else {
            $decoded_parameters = (array)$parameters;
            $params_string = json_encode($decoded_parameters, JSON_UNESCAPED_SLASHES | JSON_FORCE_OBJECT);
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
            $error_info = ["Invalid Authorization Signature", "signature mismatch: data=\n***\n".($data)."\n***\nactual signature=$signature"];
            return false;
        }

        return $valid;
    }
}
