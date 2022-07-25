<?php

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class AuthsignalClient
{
  public static function apiUrl($url='')
  {
    $apiEndpoint = getenv('AUTHSIGNAL_SERVER_API_ENDPOINT');
    if ( !$apiEndpoint ) {
      $apiBase    = Authsignal::$apiHostname;
      $apiVersion = Authsignal::getApiVersion();
      $apiEndpoint = $apiBase.'/'.$apiVersion;
    }
    
    return $apiEndpoint.$url;
  }

  public function handleApiError($response, $status)
  {
    $type = $response['error'];
    $msg  = $response['message'];
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
    $response = json_decode($request->getBody(), true);
    if (!empty($request->rBody) && $response === null) {
      throw new AuthsignalApiError('Invalid response from API', 'api_error', $request->rStatus);
    }

    if ($request->getStatusCode() < 200 || $request->getStatusCode() >= 300) {
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

  public function send($url, $payload, $method = 'post')
  {
    $this->preCheck();

    $client = new Client([
      'headers' => [                                                                                                                                                                   
        'Authorization' => ['Basic '.base64_encode(Authsignal::getApiKey().':')],                                                                                                 
      ]
    ]);

    try {
      $response = $client->request($method , self::apiUrl($url), [ "json" => $payload ]);
    } catch (RequestException $e) {
      $response = $e->getResponse();
      $this->handleApiError(json_decode($response->getBody(), true), $response->getStatusCode());
    }

    $this->handleResponse($response);
  }
}
