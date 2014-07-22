<?php

use Utipd\HmacAuth\Generator;
use \Exception;
use \PHPUnit_Framework_Assert as PHPUnit;

/*
* 
*/
class GeneratorTest extends \PHPUnit_Framework_TestCase
{


    public function testCreateSignature() {
        $generator = new Generator();
        $params = $generator->createSignatureParameters('GET', 'http://somesite.com/sample/url', ['foo' => 'bar'], 'myapi123', 'mysecret456');
        PHPUnit::assertGreaterThanOrEqual(time(), $params['nonce']);

        $expected_signature = $this->expectedSignature($params['nonce']);
        PHPUnit::assertEquals($expected_signature, $params['signature']);
    } 



    public function testSignRequest() {
        $client = new \GuzzleHttp\Client();
        $request = $client->createRequest('GET', 'http://somesite.com/sample/url?foo=bar');

        $generator = new Generator();
        $generator->addSignatureToGuzzleRequest($request, 'myapi123', 'mysecret456');

        PHPUnit::assertEquals('myapi123', $request->getHeader('X-UTIPD-AUTH-API-TOKEN'));
        $nonce = $request->getHeader('X-UTIPD-AUTH-NONCE');
        PHPUnit::assertGreaterThanOrEqual(time(), $nonce);
        $expected_signature = $this->expectedSignature($nonce);
        PHPUnit::assertEquals($expected_signature, $request->getHeader('X-UTIPD-AUTH-SIGNATURE'));
    } 



    protected function expectedSignature($nonce) {
        $str = "GET\nhttp://somesite.com/sample/url\n".json_encode((array)['foo' => 'bar'])."\nmyapi123\n".$nonce;
        return base64_encode(hash_hmac('sha256', $str, 'mysecret456', true));
    }

}
