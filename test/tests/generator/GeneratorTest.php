<?php

use Tokenly\HmacAuth\Generator;
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

    public function testSignGuzzleRequest() {
        $client = new \GuzzleHttp\Client();
        $request = new \GuzzleHttp\Psr7\Request('GET', 'http://somesite.com/sample/url?foo=bar');

        $generator = new Generator();
        $request = $generator->addSignatureToGuzzle6Request($request, 'myapi123', 'mysecret456');

        PHPUnit::assertEquals(['myapi123'], $request->getHeader('X-TOKENLY-AUTH-API-TOKEN'));
        $nonce = $request->getHeader('X-TOKENLY-AUTH-NONCE')[0];
        PHPUnit::assertGreaterThanOrEqual(time(), $nonce);
        $expected_signature = $this->expectedSignature($nonce);
        PHPUnit::assertEquals([$expected_signature], $request->getHeader('X-TOKENLY-AUTH-SIGNATURE'));

        // test DELETE with query params
        $request = new \GuzzleHttp\Psr7\Request('DELETE', 'http://somesite.com/sample/url?foo=bar');
        $request = $generator->addSignatureToGuzzle6Request($request, 'myapi123', 'mysecret456');
        $expected_signature = $this->expectedSignature($nonce, 'DELETE');
        PHPUnit::assertEquals([$expected_signature], $request->getHeader('X-TOKENLY-AUTH-SIGNATURE'));
    }

    public function testSignSymfonyRequest() {
        $request = Symfony\Component\HttpFoundation\Request::create('http://somesite.com/sample/url', 'GET', ['foo' => 'bar']);

        $generator = new Generator();
        $request = $generator->addSignatureToSymfonyRequest($request, 'myapi123', 'mysecret456');

        $nonce = $request->headers->get('X-TOKENLY-AUTH-NONCE');
        PHPUnit::assertGreaterThanOrEqual(time(), $nonce);
        PHPUnit::assertEquals('myapi123', $request->headers->get('X-TOKENLY-AUTH-API-TOKEN'));
        $expected_signature = $this->expectedSignature($nonce);
        PHPUnit::assertEquals($expected_signature, $request->headers->get('X-TOKENLY-AUTH-SIGNATURE'));

        // test DELETE with query params
        $request = Symfony\Component\HttpFoundation\Request::create('http://somesite.com/sample/url', 'DELETE', ['foo' => 'bar']);
        $request = $generator->addSignatureToSymfonyRequest($request, 'myapi123', 'mysecret456');
        $expected_signature = $this->expectedSignature($nonce, 'DELETE');
        PHPUnit::assertEquals($expected_signature, $request->headers->get('X-TOKENLY-AUTH-SIGNATURE'));
    }

    public function testGenerateHeaders() {
        $generator = new Generator();
        $headers = $generator->addSignatureToHeadersArray('GET', 'http://somesite.com/sample/url', ['foo' => 'bar'], 'myapi123', 'mysecret456');

        $nonce = $headers['X-TOKENLY-AUTH-NONCE'];
        PHPUnit::assertGreaterThanOrEqual(time(), $nonce);
        PHPUnit::assertEquals('myapi123', $headers['X-TOKENLY-AUTH-API-TOKEN']);
        $expected_signature = $this->expectedSignature($nonce);
        PHPUnit::assertEquals($expected_signature, $headers['X-TOKENLY-AUTH-SIGNATURE']);


        // with GET params
        $headers = $generator->addSignatureToHeadersArray('GET', 'http://somesite.com/sample/url?foo=bar', null, 'myapi123', 'mysecret456');

        $nonce = $headers['X-TOKENLY-AUTH-NONCE'];
        PHPUnit::assertGreaterThanOrEqual(time(), $nonce);
        PHPUnit::assertEquals('myapi123', $headers['X-TOKENLY-AUTH-API-TOKEN']);
        $expected_signature = $this->expectedSignature($nonce);
        PHPUnit::assertEquals($expected_signature, $headers['X-TOKENLY-AUTH-SIGNATURE']);
    }


    // ------------------------------------------------------------------------
    
    protected function expectedSignature($nonce, $http_method='GET') {
        $str = "{$http_method}\nhttp://somesite.com/sample/url\n".json_encode((array)['foo' => 'bar'])."\nmyapi123\n".$nonce;
        return base64_encode(hash_hmac('sha256', $str, 'mysecret456', true));
    }

}
