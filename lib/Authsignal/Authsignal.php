<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

abstract class Authsignal
{
  const VERSION = '3.0.1';

  public static $apiKey;

  public static $apiHostname = 'https://signal.authsignal.com';

  public static $apiVersion = 'v1';

  private static $curlOpts = array();
  private static $validCurlOpts = array(CURLOPT_CONNECTTIMEOUT,
                                        CURLOPT_CONNECTTIMEOUT_MS,
                                        CURLOPT_TIMEOUT,
                                        CURLOPT_TIMEOUT_MS);

  public static function getApiKey()
  {
    return self::$apiKey;
  }

  public static function setApiKey($apiKey)
  {
    self::$apiKey = $apiKey;
  }

  public static function setApiHostname($hostname)
  {
    self::$apiHostname = $hostname;
  }

  public static function setCurlOpts($curlOpts)
  {
    $invalidOpts = array_diff(array_keys($curlOpts), self::$validCurlOpts);
    // If any options are invalid.
    if (count($invalidOpts)) {
      // Throw an exception listing all invalid options.
      throw new AuthsignalCurlOptionError('These cURL options are not allowed:' .
                                       join(',', $invalidOpts));
    }
    // May seem odd, but one may want the option of stripping them out, and so
    // would probably simply use error_log instead of throw.
    self::$curlOpts = array_diff($curlOpts, array_flip($invalidOpts));
  }

  public static function getCurlOpts()
  {
    return self::$curlOpts;
  }

  public static function getApiVersion()
  {
    return self::$apiVersion;
  }

  public static function setApiVersion($apiVersion)
  {
    self::$apiVersion = $apiVersion;
  }

  /**
   * Track an action
   * 
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   *                      - string 'action': The action code that you are tracking
   *                      - array 'attributes': An array of attributes to track
   * @return array The authsignal response
   */
  public static function track(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $action = urlencode($params['action']);
    $attributes = $params['attributes'];
    list($response, $request) = $request->send("/users/{$userId}/actions/{$action}", $attributes, 'post');
    
    return $response;
  }

  /**
   * Get an action
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   *                      - string 'action': The action code that you are tracking
   *                      - string 'idempotencyKey': The idempotency key for the action
   * @return Array  The authsignal response
   */
  public static function getAction(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $action = urlencode($params['action']);
    $idempotencyKey = urlencode($params['idempotencyKey']);
    list($response, $request) = $request->send("/users/{$userId}/actions/{$action}/{$idempotencyKey}", array(), 'get');

    return $response;
  }

  /**
   * Get a user
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   *                      - string|null 'redirectUrl': The redirectUrl if using the redirect flow (optional)
   * @return Array  The authsignal response
   */
  public static function getUser(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $redirectUrl = isset($params['redirectUrl']) ? urlencode($params['redirectUrl']) : null;

    $path = empty($redirectUrl) ? "/users/{$userId}" : "/users/{$userId}?redirectUrl={$redirectUrl}";
    list($response, $request) = $request->send($path, null, 'get');

    return $response;
  }

  public static function updateUser(array $params)
  {
      $request = new AuthsignalClient();
      $userId = urlencode($params['userId']);
      $data = $params['data'];
      $path = "/users/{$userId}";
      list($response, $request) = $request->send($path, $data, 'post');
      return $response;
  }
  

  /**
   * Enroll Authenticators
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   *                      - array 'authenticator': The authenticator object
   * @return Array  The authsignal response
   */
  public static function enrollVerifiedAuthenticator(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $authenticator = $params['authenticator'];
    list($response, $request) = $request->send("/users/{$userId}/authenticators", $authenticator, 'post');

    return $response;
  }

  /**
   * Delete a user
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you want to delete
   * @return Array  The authsignal response
   */
  public static function deleteUser(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $path = "/users/{$userId}";
    list($response, $request) = $request->send($path, null, 'delete');
    return $response;
  }

  /**
   * Delete a user authenticator
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user
   *                      - string 'userAuthenticatorId': The userAuthenticatorId of the authenticator
   * @return Array  The authsignal response
   */
  public static function deleteAuthenticator(array $params) {
    if (empty($params['userId'])) {
        throw new InvalidArgumentException('user_id cannot be empty');
    }

    if (empty($params['userAuthenticatorId'])) {
        throw new InvalidArgumentException('user_authenticator_id cannot be empty');
    }

    $userId = urlencode($params['userId']);
    $userAuthenticatorId = urlencode($params['userAuthenticatorId']);
    $path = "/users/{$userId}/authenticators/{$userAuthenticatorId}";

    $request = new AuthsignalClient();

    try {
        list($response, $request) = $request->send($path, null, 'delete');
        return $response;
    } catch (Exception $e) {
        throw new AuthsignalApiException($e->getMessage(), $path, $e);
    }
  }

  /**
   * Validate Challenge
   * @param array $params An associative array of parameters:
   *                      - string 'token': The JWT token string returned on a challenge response
   *                      - string|null 'userId': The userId of the user you are tracking the action for (optional)
   *                      - string|null 'action': The action code that you are tracking (optional)
   * @return Array  The authsignal response
   */
  public static function validateChallenge(array $params)
  {
    $request = new AuthsignalClient();

    $payload = [
      'userId' => $params['userId'] ?? null,
      'action' => $params['action'] ?? null,
      'token' => $params['token']
    ];

    list($response, $request) = $request->send("/validate", $payload, 'post');
    
    if (isset($response['actionCode'])) {
        unset($response['actionCode']);
    }
    
    return $response;
  }

  /**
   * Update Action
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user to update the action for
   *                      - string 'action': The action code to update
   *                      - string 'idempotencyKey': The idempotency key for the action
   *                      - array 'attributes': Additional attributes for the action
   * @return array   The Authsignal response
   */
  public static function updateAction(array $params)
  {
    $request = new AuthsignalClient();
    $path = "/users/" . urlencode($params['userId']) . "/actions/" . urlencode($params['action']) . "/" . urlencode($params['idempotencyKey']);

    list($response, $request) = $request->send($path, $params['attributes'], 'patch');
    return $response;
  }

}
