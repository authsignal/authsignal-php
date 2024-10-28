<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

abstract class Authsignal
{
  const VERSION = '2.0.3';

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
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  string  $action The action code that you are tracking
   * @param  Array  $payload An array of attributes to track.
   * @return Array  The authsignal response
   */
  public static function track(string $userId, string $action, Array $payload)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    $action = urlencode($action);
    list($response, $request) = $request->send("/users/{$userId}/actions/{$action}", $payload, 'post');
    
    return $response;
  }

  /**
   * Get an action
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  string  $action The action code that you are tracking
   * @param  string  $idempotencyKey The action code that you are tracking
   * @return Array  The authsignal response
   */
  public static function getAction(string $userId, string $action, string $idempotencyKey)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    $action = urlencode($action);
    list($response, $request) = $request->send("/users/{$userId}/actions/{$action}/{$idempotencyKey}", array(), 'get');

    return $response;
  }

  /**
   * Get a user
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  string  $redirectUrl The redirectUrl if using the redirect flow (optional)
   * @return Array  The authsignal response
   */
  public static function getUser(string $userId, string $redirectUrl = null)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);

    $redirectUrl = empty($redirectUrl) ? null : urlencode($redirectUrl);
  
    $path = empty($redirectUrl) ? "/users/{$userId}" : "/users/{$userId}?redirectUrl={$redirectUrl}";
    list($response, $request) = $request->send($path, null, 'get');

    return $response;
  }

  public static function updateUser(string $userId, array $data)
  {
      $request = new AuthsignalClient();
      $userId = urlencode($userId);
      $path = "/users/{$userId}";
      list($response, $request) = $request->send($path, $data, 'post');
      return $response;
  }
  

  /**
   * Enroll Authenticators
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  Array   $authenticator The authenticator object
   * @return Array  The authsignal response
   */
  public static function enrollVerifiedAuthenticator(string $userId, Array $authenticator)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    list($response, $request) = $request->send("/users/{$userId}/authenticators", $authenticator, 'post');

    return $response;
  }

  /**
   * Delete a user
   * @param  string  $userId The userId of the user you want to delete
   * @return Array  The authsignal response
   */
  public static function deleteUser(string $userId)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    $path = "/users/{$userId}";
    list($response, $request) = $request->send($path, null, 'delete');
    return $response;
  }

  /**
   * Delete a user authenticator
   * @param  string  $userId The userId of the user
   * @param  string  $userAuthenticatorId The userAuthenticatorId of the authenticator
   * @return Array  The authsignal response
  */
  public static function deleteAuthenticator(string $userId, string $userAuthenticatorId) {
    if (empty($userId)) {
        throw new InvalidArgumentException('user_id cannot be empty');
    }

    if (empty($userAuthenticatorId)) {
        throw new InvalidArgumentException('user_authenticator_id cannot be empty');
    }

    $userId = urlencode($userId);
    $userAuthenticatorId = urlencode($userAuthenticatorId);
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
   * Validates the token returned on a challenge response, this is a critical security measure
   * also performs a back-end call to validate the state
   * @param  string|null  $userId The userId of the user you are tracking the action for
   * @param  string  $token  The JWT token string returned on a challenge response
   * @return Array  The authsignal response
   */
  public static function validateChallenge(string $token, ?string $userId = null, ?string $action = null)
  {
    $request = new AuthsignalClient();

    $payload = [
      'userId' => $userId,
      'action' => $action,
      'token' => $token
    ];

    $payload = array_filter($payload, function($value) {
      return $value !== null;
    });

    list($response, $request) = $request->send("/validate", $payload, 'post');
    
    return $response;
  }
}
