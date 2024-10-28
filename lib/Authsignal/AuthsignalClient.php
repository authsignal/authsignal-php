<?php

class AuthsignalClient
{
  public static function apiUrl($path='')
  {
    $apiEndpoint = getenv('AUTHSIGNAL_SERVER_API_ENDPOINT');
    if ( !$apiEndpoint ) {
      $apiBase    = Authsignal::$apiHostname;
      $apiVersion = Authsignal::getApiVersion();
      $apiEndpoint = $apiBase.'/'.$apiVersion;
    }
    return $apiEndpoint.$path;
  }

  public function handleApiError($response, $status)
  {
    $type = $response['error'] ?? null;
    $msg  = $response['errorDescription'] ?? null;
    switch ($status) {
      case 400:
        throw new AuthsignalBadRequest($msg, $type, $status);
      case 401:
        throw new AuthsignalUnauthorizedError($msg, $type, $status);
      case 403:
        throw new AuthsignalForbiddenError($msg, $type, $status);
      case 404:
        throw new AuthsignalNotFoundError($msg, $type, $status);
      case 422:
        // Handle subtype errors
        switch($type) {
          case 'invalid_request_token':
            throw new AuthsignalInvalidRequestTokenError($msg, $type, $status);
          default:
            throw new AuthsignalInvalidParametersError($msg, $type, $status);
        }
      default:
        throw new AuthsignalApiError($msg, $type, $status);
    }
  }

  public function handleRequestError($request)
  {
    throw new AuthsignalRequestError("$request->rError: $request->rMessage");
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

    if ($request->rStatus < 200 || $request->rStatus >= 300) {
      $this->handleApiError($response, $request->rStatus);
    }

    return array($response, $request);
  }

  public function preCheck()
  {
    $key = Authsignal::getApiKey();
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
