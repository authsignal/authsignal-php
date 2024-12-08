<?php

class AuthsignalClient
{
  public static function apiUrl($path='')
  {
    $apiEndpoint = getenv('AUTHSIGNAL_SERVER_API_ENDPOINT');
    if ( !$apiEndpoint ) {
      $apiURL    = Authsignal::$apiUrl;
      $apiVersion = Authsignal::getApiVersion();
      $apiEndpoint = $apiURL.'/'.$apiVersion;
    }
    return $apiEndpoint.$path;
  }

  public function handleApiError($response, $statusCode)
  {
    $errorCode = $response['errorCode'] ?? null;
    $errorDescription  = $response['errorDescription'] ?? null;
    switch ($statusCode) {
      case 400:
        throw new AuthsignalBadRequest($statusCode, $errorCode, $errorDescription);
      case 401:
        throw new AuthsignalUnauthorizedError($statusCode, $errorCode, $errorDescription);
      case 403:
        throw new AuthsignalForbiddenError($statusCode, $errorCode, $errorDescription);
      case 404:
        throw new AuthsignalNotFoundError($statusCode, $errorCode, $errorDescription);
      case 422:
        // Handle subtype errors
        switch($errorCode) {
          case 'invalid_request_token':
            throw new AuthsignalInvalidRequestTokenError($statusCode, $errorCode, $errorDescription);
          default:
            throw new AuthsignalInvalidParametersError($statusCode, $errorCode, $errorDescription);
        }
      default:
        throw new AuthsignalApiError($statusCode, $errorCode, $errorDescription);
    }
  }

  public function handleRequestError($request)
  {
      $statusCode = $request->rStatus; // HTTP statusCode code
      $errorCode = $request->rError; // Error code
      $errorDescription = $request->rMessage; // Error message
    
      throw new AuthsignalRequestError($statusCode, $errorCode, $errorDescription);
  }

  public function handleResponse($request)
  {
    if ($request->rError) {
      $this->handleRequestError($request);
    }

    $response = json_decode($request->rBody, true);
    if (!empty($request->rBody) && $response === null) {
      throw new AuthsignalApiError('Invalid response from API', 'api_error', $request->rStatus);
    }

    if ($request->rStatus < 200 || $request->rStatus >= 400) {
      $this->handleApiError($response, $request->rStatus);
    }

    return array($response, $request);
  }

  public function preCheck()
  {
    $key = Authsignal::getApiSecretKey();
    if (empty($key)) {
      throw new AuthsignalConfigurationError();
    }
  }

  public function send($path, $payload = null, $method = 'post', $filterNullValues = true)
  {
    if ($filterNullValues && is_array($payload)) {
      $payload = array_filter($payload, function($value) {
        return $value !== null;
      });
    }

    $this->preCheck();

    $request = new AuthsignalRequestTransport();
    $request->send($method, self::apiUrl($path), $payload);

    return $this->handleResponse($request);
  }
}
