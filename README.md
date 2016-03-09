# Overview

The HMAC authentication component for Tokenly.

[![Build Status](https://travis-ci.org/tokenly/hmac-auth.svg?branch=master)](https://travis-ci.org/tokenly/hmac-auth)


# Authentication

To authenticate HTTP requests that use this component, you must include 3 HTTP headers with your request:

1. X-Tokenly-Auth-Api-Token
2. X-Tokenly-Auth-Nonce
3. X-Tokenly-Auth-Signature

To generate these headers, you will need an API Token and a secret API Key.  


Say my API Token is `TWKTkwIQDTvirh6D` and my API Secret key is `Kun2M2UladalYAeUvXyiKWhFuwrsmSreM841K45O`.  Here is an explanation of each header.

### X-Tokenly-Auth-Api-Token

This token is nothing more than the API Token.

Example:
`X-Tokenly-Auth-Api-Token: TWKTkwIQDTvirh6D`


### X-Tokenly-Auth-Nonce

The nonce header is the current unix timestamp in seconds.

Example:
`X-Tokenly-Auth-Nonce: 1457530047`


### X-Tokenly-Auth-Signature

The signature is a base64 encoded string using sha256 HMAC.  The key for the hash is the API Key.  And the message is generated using the following data:

```
{METHOD}\n
{URL}\n
{PARAMETERS}\n
{API TOKEN}\n
{NONCE}
```

{METHOD} is the http method such as GET,POST,PUT,DELETE
{URL} is the full URL of the api endpoint
{PARAMETERS} are required and should be a JSON encoded string representing the parameters.  For empty parameters, use `{}`.
{API TOKEN} and {NONCE} are the same as send in the headers.

Items are separated with a single newline character.

After calculating the HMAC, encode the data in base64 format.


Example:

Using the values above and a request of GET https://www.example.com/api/v1/mystuff, the signature header will be:

`X-Tokenly-Auth-Signature: hZ6SDgcZzo5AYrS9yopEQo068ax0NojG/CfXWG+RJEA`


