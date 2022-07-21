<?php

abstract class Authsignal
{
  const VERSION = '0.1.0';

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
   * Enrol Authenticators
   * @param  string  $userId The userId of the user you are tracking the action for
   * @param  Array   $authenticator The authenticator object
   * @return Array  The authsignal response
   */
  public static function enrolAuthenticator(string $userId, Array $authenticator)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($userId);
    list($response, $request) = $request->send("/users/${userId}/authenticators", $authenticator, 'post');

    return $response;
  }

}
