<?php

namespace Tokenly\HmacAuth\Exception;

use Exception;

/*
* AuthorizationException
*/
class AuthorizationException extends Exception
{

    public function __construct($authorization_error, $internal_message=null, $code=null) {
        if ($internal_message === null) { $internal_message = $authorization_error; }
        if ($code === null) { $code=403; }
        parent::__construct($internal_message, $code, null);

        $this->setAuthorizationErrorString($authorization_error);
    }

    public function setAuthorizationErrorString($authorization_error) {
        $this->authorization_error = $authorization_error;
    }
    public function getAuthorizationErrorString() {
        return $this->authorization_error;
    }


}
