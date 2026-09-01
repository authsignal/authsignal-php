<?php

class AuthsignalRequestTransport
{
  public $rBody;
  public $rHeaders;
  public $rStatus;
  public $rError;
  public $rMessage;

  private function setResponse($curl)
  {
    $response = curl_exec($curl);

    $this->rError = null;
    $this->rMessage = null;
    $this->rBody = null;
    $this->rStatus = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    $this->rHeaders = array();

    if ($response == false) {
      $this->rError   = curl_errno($curl);
      $this->rMessage = curl_error($curl);
    }
    else {
      $header_size = curl_getinfo($curl, CURLINFO_HEADER_SIZE);
      $this->rBody = substr($response, $header_size);
      $headers_string = substr($response, 0, $header_size);
      $headers_array = explode("\r\n", str_replace("\r\n\r\n", '', $headers_string));
      # Convert headers into an associative array
      foreach ($headers_array as $header) {
        preg_match('#(.*?)\:\s(.*)#', $header, $matches);
        if (!empty($matches[1])) {
          $this->rHeaders[$matches[1]] = $matches[2];
        }
      }
    }
  }

  private function isReplayable($method, $url, $payload)
  {
    if (in_array($method, array('get', 'head', 'options'))) {
      return true;
    }

    if (is_array($payload) && !empty($payload['idempotencyKey'])) {
      return true;
    }

    return $method === 'patch' && preg_match('#/actions/[^/]+/[^/]+$#', parse_url($url, PHP_URL_PATH));
  }

  private function isTransientCurlError($error)
  {
    return in_array($error, array(
      CURLE_COULDNT_CONNECT,
      CURLE_OPERATION_TIMEDOUT,
      CURLE_SEND_ERROR,
      CURLE_RECV_ERROR,
      CURLE_GOT_NOTHING,
      CURLE_PARTIAL_FILE
    ));
  }

  private function shouldRetry($method, $url, $payload, $retryCount)
  {
    if ($retryCount >= Authsignal::getRetries() || !$this->isReplayable($method, $url, $payload)) {
      return false;
    }

    if ($this->rError && $this->isTransientCurlError($this->rError)) {
      return true;
    }

    return $this->rStatus === 429 || ($this->rStatus >= 500 && $this->rStatus <= 599);
  }

  private function retryDelayMilliseconds($retryCount)
  {
    $baseDelay = 100 * pow(2, $retryCount);
    $delay = $baseDelay + random_int(0, (int) ($baseDelay * 0.2));

    $retryAfter = null;
    foreach ($this->rHeaders as $name => $value) {
      if (strcasecmp($name, 'Retry-After') === 0) {
        $retryAfter = $value;
        break;
      }
    }

    if ($this->rStatus === 429 && $retryAfter !== null) {
      $retryAfterMs = is_numeric($retryAfter)
        ? ((float) $retryAfter * 1000)
        : max(0, (strtotime($retryAfter) - time()) * 1000);
      $delay = max($delay, $retryAfterMs);
    }

    return (int) $delay;
  }

  public function send($method, $url, $payload) {
    $method = strtolower($method);
    $body = empty($payload) ? null : json_encode($payload);
    $retryCount = 0;

    do {
      $curl = curl_init();
      $curlOptions = array();

      switch($method) {
        case 'post':
        case 'put':
        case 'patch':
        case 'delete':
          $curlOptions[CURLOPT_CUSTOMREQUEST] = strtoupper($method);
          break;
        case 'get':
          $curlOptions[CURLOPT_HTTPGET] = true;
          break;
        default:
          throw new AuthsignalRequestError();
      }

      if ($body) {
        $curlOptions[CURLOPT_POSTFIELDS] = $body;
      }

      $curlOptions[CURLOPT_URL] = $url;
      $curlOptions[CURLOPT_USERPWD] = Authsignal::getApiSecretKey() . ":";
      $curlOptions[CURLOPT_RETURNTRANSFER] = true;
      $curlOptions[CURLOPT_CONNECTTIMEOUT] = 3;
      $curlOptions[CURLOPT_TIMEOUT] = 10;
      $curlOptions[CURLOPT_HTTPHEADER] = array(
        'Content-Type: application/json',
        'Content-Length: ' . (is_null($body) ? 0 : strlen($body)),
        'X-Authsignal-Version: ' . Authsignal::VERSION,
        'User-Agent: authsignal-php'
      );
      $curlOptions[CURLOPT_HEADER] = true;

      $userOptions = Authsignal::getCurlOpts();
      curl_setopt_array($curl, $userOptions + $curlOptions);
      $this->setResponse($curl);
      curl_close($curl);

      if (!$this->shouldRetry($method, $url, $payload, $retryCount)) {
        break;
      }

      usleep($this->retryDelayMilliseconds($retryCount) * 1000);
      $retryCount++;
    } while (true);
  }
}
