<?php

class AuthsignalError extends Exception
{
    public function __construct($statusCode, $errorCode, $errorDescription = null, $previous = null)
    {
        $message = $this->formatMessage($statusCode, $errorCode, $errorDescription);
        parent::__construct($message, $statusCode, $previous);
    }

    private function formatMessage($statusCode, $errorCode, $errorDescription = null)
    {
        return "$statusCode - " . $this->formatDescription($errorCode, $errorDescription);
    }

    private function formatDescription($errorCode, $errorDescription = null)
    {
        return $errorDescription && strlen($errorDescription) > 0 ? $errorDescription : $errorCode;
    }
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
