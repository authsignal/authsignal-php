<?php

class AuthsignalError extends Exception
{

}

class AuthsignalRequestError extends AuthsignalError
{

}

class AuthsignalConfigurationError extends AuthsignalError
{

}

class AuthsignalCurlOptionError extends AuthsignalError
{

}

class AuthsignalApiError extends AuthsignalError
{
  public function __construct($msg, $type = null, $status = null)
  {
    parent::__construct($msg);
    $this->type = $type;
    $this->httpStatus = $status;
  }
}

class AuthsignalBadRequest extends AuthsignalApiError
{

}

class AuthsignalUnauthorizedError extends AuthsignalApiError
{

}

class AuthsignalForbiddenError extends AuthsignalApiError
{

}

class AuthsignalNotFoundError extends AuthsignalApiError
{

}

class AuthsignalInvalidParametersError extends AuthsignalApiError
{

}

class AuthsignalInvalidRequestTokenError extends AuthsignalInvalidParametersError
{

}
