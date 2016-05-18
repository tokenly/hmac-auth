<?php

use Tokenly\HmacAuth\Validator;
use \PHPUnit_Framework_Assert as PHPUnit;

/*
* 
*/
class ValidatorTest extends \PHPUnit_Framework_TestCase
{


    public function testValidateComponents() {
        $validator = $this->newValidator();

        $nonce = time();
        $expected_signature = $this->expectedSignature($nonce);

        // will throw an exception if it fails
        $validator->validate('GET', 'http://somesite.com/sample/url', ['foo' => 'bar'], null, 'myapi123', $nonce, $expected_signature, 'mysecret456', $error_info);
        PHPUnit::assertEmpty($error_info);
    } 

    public function testValidateFromRequest() {
        $validator = $this->newValidator();

        $nonce = time();
        $expected_signature = $this->expectedSignature($nonce);

        // $uri, $method = 'GET', $parameters = array(), $cookies = array(), $files = array(), $server = array()
        $request = \Symfony\Component\HttpFoundation\Request::create('http://somesite.com/sample/url?foo=bar', 'GET', [], [], [], []);
        $request->headers->set('X-Tokenly-Auth-Api-Token', 'myapi123');
        $request->headers->set('X-Tokenly-Auth-Nonce',     $nonce);
        $request->headers->set('X-Tokenly-Auth-Signature', $expected_signature);

        $params = $validator->validateFromRequest($request);
    } 


    public function testValidateWithAlternateSignedURL() {
        $validator = $this->newValidator();

        $nonce = time();
        $expected_signature = $this->expectedSignature($nonce, 'http://proxysite.com');

        // $uri, $method = 'GET', $parameters = array(), $cookies = array(), $files = array(), $server = array()
        $request = \Symfony\Component\HttpFoundation\Request::create('http://somesite.com/sample/url?foo=bar', 'GET', [], [], [], []);
        $request->headers->set('X-Tokenly-Auth-Api-Token',  'myapi123');
        $request->headers->set('X-Tokenly-Auth-Nonce',      $nonce);
        $request->headers->set('X-Tokenly-Auth-Signature',  $expected_signature);
        $request->headers->set('X-Tokenly-Auth-Signed-Url', 'http://proxysite.com/sample/url');

        $validator->setSignedURLValidationFunction(function($actual_url, $signed_url) {
            if ($signed_url != 'http://proxysite.com/sample/url') {
                throw new Exception("Unexpected Signed URL of {$signed_url}", 1);
            }

            $is_valid = true;
            return $is_valid;
        });

        $params = $validator->validateFromRequest($request);
    } 


    ////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////

    protected function expectedSignature($nonce, $url='http://somesite.com') {
        $str = "GET\n{$url}/sample/url\n".json_encode((array)['foo' => 'bar'])."\nmyapi123\n".$nonce;
        return base64_encode(hash_hmac('sha256', $str, 'mysecret456', true));
    }


    protected function newValidator() {
        $validator = new Validator(function($api_token) {
            if ($api_token === 'myapi123') { return 'mysecret456'; }
            throw new Exception("Unknown api token: $api_token", 1);
        });
        return $validator;
    }
}
