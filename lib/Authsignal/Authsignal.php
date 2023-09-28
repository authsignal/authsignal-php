<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

abstract class Authsignal
{
  const VERSION = '0.1.5';

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
   * @param  string  $actionCode The action code that you are tracking
   * @param  Array  $payload An array of attributes to track.
   * @return Array  The authsignal response
   */
  public static function trackAction(string $userId, string $actionCode, Array $payload)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    $actionCode = urlencode($actionCode);
    list($response, $request) = $request->send("/users/${userId}/actions/${actionCode}", $payload, 'post');
    
    return $response;
  }

  /**
   * Get an action
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  string  $actionCode The action code that you are tracking
   * @param  string  $idempotencyKey The action code that you are tracking
   * @return Array  The authsignal response
   */
  public static function getAction(string $userId, string $actionCode, string $idempotencyKey)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    $actionCode = urlencode($actionCode);
    list($response, $request) = $request->send("/users/${userId}/actions/${actionCode}/${idempotencyKey}", array(), 'get');

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
  
    $path = empty($redirectUrl) ? "/users/${userId}" : "/users/${userId}?redirectUrl=${redirectUrl}";
    list($response, $request) = $request->send($path, null, 'get');

    return $response;
  }

  /**
   * Identify
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  Array  $user The user object with email
   * @return Array  The authsignal response
   */
  public static function identify(string $userId, Array $user)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    list($response, $request) = $request->send("/users/${userId}", $user, 'post');

    return $response;
  }

  /**
   * @deprecated
   * Enrol Authenticators
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  Array   $authenticator The authenticator object
   * @return Array  The authsignal response
   */
  public static function enrolAuthenticator(string $userId, Array $authenticator)
  {
    $response = self::enrollAuthenticator($userId, $authenticator);

    return $response;
  }

  /**
   * Enroll Authenticators
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  Array   $authenticator The authenticator object
   * @return Array  The authsignal response
   */
  public static function enrollAuthenticator(string $userId, Array $authenticator)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    list($response, $request) = $request->send("/users/${userId}/authenticators", $authenticator, 'post');

    return $response;
  }

  /**
   * Validate Challenge
   * Validates the token returned on a challenge response, this is a critical security measure
   * also performs a back-end call to validate the state
   * @param  string|null  $userId The userId of the user you are tracking the action for
   * @param  string  $token  The JWT token string returned on a challenge response
   * @return Array  The authsignal response
   */
  public static function validateChallenge(string $token, ?string $userId = null)
  {
    $key = self::getApiKey();
    $decoded = (array)JWT::decode($token, new Key($key, 'HS256'));
    $otherClaim = (array)$decoded['other'];

    $decodedUserId = $otherClaim["userId"];
    $decodedActionCode = $otherClaim["actionCode"];
    $decodedIdempotencyKey= $otherClaim["idempotencyKey"];

    if ($userId && ($userId != $decodedUserId))
    {
      return [
        "userId"  => $decodedUserId,
        "success" => false,
        "state" => null
      ];
    }

    if($decodedActionCode && $decodedIdempotencyKey){
      $action = self::getAction($decodedUserId, $decodedActionCode, $decodedIdempotencyKey);

      if($action){
        $success = $action["state"] === "CHALLENGE_SUCCEEDED";
        return [
          "userId"  => $decodedUserId,
          "success" => $success,
          "state" => $action["state"]
        ];
      }
    }

    return [
      "userId"  => $decodedUserId,
      "success" => false,
      "state" => null
    ];
  }

}
