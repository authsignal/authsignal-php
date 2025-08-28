<?php

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

abstract class Authsignal
{
  const VERSION = '4.3.0';

  public static $apiSecretKey;
  public static $webhook;

  public static $apiUrl = 'https://signal.authsignal.com';

  private static $curlOpts = array();
  private static $validCurlOpts = array(CURLOPT_CONNECTTIMEOUT,
                                        CURLOPT_CONNECTTIMEOUT_MS,
                                        CURLOPT_TIMEOUT,
                                        CURLOPT_TIMEOUT_MS);

  public static function getApiSecretKey()
  {
    return self::$apiSecretKey;
  }

  public static function setApiSecretKey($apiSecretKey)
  {
    self::$apiSecretKey = $apiSecretKey;
  }

  public static function setApiUrl($apiUrl)
  {
    self::$apiUrl = $apiUrl;
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

  public static function webhook(): \Authsignal\Webhook
  {
    if (!self::$apiSecretKey) {
      throw new \Exception('apiSecretKey is not set.');
    }
    if (!self::$webhook) {
      self::$webhook = new \Authsignal\Webhook(self::$apiSecretKey);
    }
    return self::$webhook;
  }

  /**
   * Get a user
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   * @return Array  The authsignal response
   */
  public static function getUser(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);

    $path = "/users/{$userId}";
    list($response, $request) = $request->send($path, null, 'get');

    return $response;
  }

  /**
   * Update User
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user to update
   *                      - array 'attributes': The attributes to update for the user
   * @return array The authsignal response
   */
  public static function updateUser(array $params)
  {
      $request = new AuthsignalClient();
      $userId = urlencode($params['userId']);
      $attributes = $params['attributes'];
      $path = "/users/{$userId}";
      list($response, $request) = $request->send($path, $attributes, 'patch');
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
   * Get Authenticators
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user whose authenticators you want to retrieve
   * @return array The list of user authenticators
   * @throws AuthsignalApiException if the request fails
   */
  public static function getAuthenticators(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $path = "/users/{$userId}/authenticators";
    
    list($response, $request) = $request->send($path, null, 'get');
    return $response; 
  }


    /**
   * Enroll Authenticators
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   *                      - array 'attributes': The authenticator object
   * @return Array  The authsignal response
   */
  public static function enrollVerifiedAuthenticator(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $attributes = $params['attributes'];
    list($response, $request) = $request->send("/users/{$userId}/authenticators", $attributes, 'post');

    return $response;
  }

  /**
   * Delete an authenticator
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
   * Track an action
   * 
   * @param array $params An associative array of parameters:
   *                      - string 'userId': The userId of the user you are tracking the action for
   *                      - string 'action': The action code that you are tracking
   *                      - array 'attributes': An array of attributes to track (optional)
   * @return array The authsignal response
   */
  public static function track(array $params)
  {
    $request = new AuthsignalClient();
    $userId = urlencode($params['userId']);
    $action = urlencode($params['action']);
    $attributes = isset($params['attributes']) ? $params['attributes'] : [];
    
    list($response, $request) = $request->send("/users/{$userId}/actions/{$action}", $attributes, 'post');
    
    return $response;
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

  /**
   * Challenge
   * @param array $params An associative array of parameters:
   *                      - string 'verificationMethod': The verification method (SMS, EMAIL_OTP)
   *                      - string 'action': The action code
   *                      - string|null 'email': The email address (optional)
   *                      - string|null 'phoneNumber': The phone number (optional)
   *                      - string|null 'smsChannel': The SMS channel (optional)
   * @return array The authsignal response
   */
  public static function challenge(array $params)
  {
    $request = new AuthsignalClient();
    
    $payload = [
      'verificationMethod' => $params['verificationMethod'],
      'action' => $params['action'],
      'email' => $params['email'] ?? null,
      'phoneNumber' => $params['phoneNumber'] ?? null,
      'smsChannel' => $params['smsChannel'] ?? null
    ];

    list($response, $request) = $request->send("/challenge", $payload, 'post');
    return $response;
  }

  /**
   * Verify
   * @param array $params An associative array of parameters:
   *                      - string 'challengeId': The challenge ID
   *                      - string 'verificationCode': The verification code
   * @return array The authsignal response
   */
  public static function verify(array $params)
  {
    $request = new AuthsignalClient();
    
    $payload = [
      'challengeId' => $params['challengeId'],
      'verificationCode' => $params['verificationCode']
    ];

    list($response, $request) = $request->send("/verify", $payload, 'post');
    return $response;
  }

  /**
   * Get Challenge
   * @param array $params An associative array of parameters:
   *                      - string|null 'challengeId': The challenge ID (optional)
   *                      - string|null 'userId': The user ID (optional)
   *                      - string|null 'action': The action code (optional)
   *                      - string|null 'verificationMethod': The verification method (optional)
   * @return array The authsignal response
   */
  public static function getChallenge(array $params)
  {
    $request = new AuthsignalClient();
    
    $queryParams = [];
    if (!empty($params['challengeId'])) {
        $queryParams['challengeId'] = urlencode($params['challengeId']);
    }
    if (!empty($params['userId'])) {
        $queryParams['userId'] = urlencode($params['userId']);
    }
    if (!empty($params['action'])) {
        $queryParams['action'] = urlencode($params['action']);
    }
    if (!empty($params['verificationMethod'])) {
        $queryParams['verificationMethod'] = urlencode($params['verificationMethod']);
    }

    $queryString = !empty($queryParams) ? '?' . http_build_query($queryParams) : '';
    $path = "/challenges" . $queryString;
    
    list($response, $request) = $request->send($path, null, 'get');
    return $response;
  }

  /**
   * Claim Challenge
   * @param array $params An associative array of parameters:
   *                      - string 'challengeId': The challenge ID
   *                      - string 'userId': The user ID
   *                      - bool|null 'skipVerificationCheck': Skip verification check (optional)
   *                      - string|null 'deviceId': The device ID (optional)
   *                      - string|null 'ipAddress': The IP address (optional)
   *                      - string|null 'userAgent': The user agent (optional)
   *                      - array|null 'custom': Custom data (optional)
   * @return array The authsignal response
   */
  public static function claimChallenge(array $params)
  {
    $request = new AuthsignalClient();
    
    $payload = [
      'challengeId' => $params['challengeId'],
      'userId' => $params['userId'],
      'skipVerificationCheck' => $params['skipVerificationCheck'] ?? null,
      'deviceId' => $params['deviceId'] ?? null,
      'ipAddress' => $params['ipAddress'] ?? null,
      'userAgent' => $params['userAgent'] ?? null,
      'custom' => $params['custom'] ?? null
    ];

    list($response, $request) = $request->send("/claim", $payload, 'post');
    return $response;
  }
}
