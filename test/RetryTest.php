<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use donatj\MockWebServer\MockWebServer;
use donatj\MockWebServer\DelayedResponse;
use donatj\MockWebServer\Response;
use donatj\MockWebServer\ResponseStack;

class RetryTest extends PHPUnit\Framework\TestCase {
    /** @var MockWebServer */
    private static $server;

    public static function setUpBeforeClass(): void {
        Authsignal::setApiSecretKey('secret');
        Authsignal::setRetries(2);
        self::$server = new MockWebServer;
        self::$server->start();
        Authsignal::setApiUrl(self::$server->getServerRoot());
    }

    public static function tearDownAfterClass(): void {
        self::$server->stop();
    }

    protected function setUp(): void {
        Authsignal::setRetries(2);
        Authsignal::setCurlOpts([]);
    }

    private function requestCount(): int {
        $count = 0;
        while (self::$server->getRequestByOffset($count) !== null) {
            $count++;
        }
        return $count;
    }

    public function testRetriesSafeRequestsTwiceOn5xx(): void {
        $before = $this->requestCount();
        self::$server->setResponseOfPath('/users/user', new ResponseStack(
            new Response('{}', [], 503),
            new Response('{}', [], 503),
            new Response('{"isEnrolled":false}', [], 200)
        ));

        $response = Authsignal::getUser(['userId' => 'user']);

        $this->assertFalse($response['isEnrolled']);
        $this->assertEquals(3, $this->requestCount() - $before);
    }

    public function testRetries429Responses(): void {
        $before = $this->requestCount();
        self::$server->setResponseOfPath('/users/user', new ResponseStack(
            new Response('{}', ['Retry-After' => '0'], 429),
            new Response('{"isEnrolled":false}', [], 200)
        ));

        Authsignal::getUser(['userId' => 'user']);

        $this->assertEquals(2, $this->requestCount() - $before);
    }

    public function testRetriesTransientNetworkFailures(): void {
        $before = $this->requestCount();
        Authsignal::setCurlOpts([CURLOPT_TIMEOUT => 1]);
        self::$server->setResponseOfPath('/users/user', new ResponseStack(
            new DelayedResponse(new Response('{}', [], 200), 1100000),
            new Response('{"isEnrolled":false}', [], 200)
        ));

        Authsignal::getUser(['userId' => 'user']);

        $this->assertEquals(2, $this->requestCount() - $before);
    }

    public function testRetriesIdempotentWrites(): void {
        $before = $this->requestCount();
        self::$server->setResponseOfPath('/users/user/actions/withdrawal', new ResponseStack(
            new Response('{}', [], 503),
            new Response('{"idempotencyKey":"key","state":"ALLOW"}', [], 200)
        ));

        Authsignal::track([
            'userId' => 'user',
            'action' => 'withdrawal',
            'attributes' => ['idempotencyKey' => 'key']
        ]);

        $this->assertEquals(2, $this->requestCount() - $before);
    }

    public function testDoesNotRetryNonIdempotentWritesOr499(): void {
        $beforePost = $this->requestCount();
        self::$server->setResponseOfPath('/users/user/actions/withdrawal', new Response('{}', [], 503));
        try {
            Authsignal::track(['userId' => 'user', 'action' => 'withdrawal']);
        } catch (AuthsignalApiError $error) {
            // Expected.
        }
        $this->assertEquals(1, $this->requestCount() - $beforePost);

        $beforeChallenge = $this->requestCount();
        self::$server->setResponseOfPath('/users/user', new Response('{}', [], 499));
        try {
            Authsignal::getUser(['userId' => 'user']);
        } catch (AuthsignalApiError $error) {
            // Expected.
        }
        $this->assertEquals(1, $this->requestCount() - $beforeChallenge);
    }

    public function testAllowsRetriesToBeDisabled(): void {
        Authsignal::setRetries(0);
        $before = $this->requestCount();
        self::$server->setResponseOfPath('/users/user', new Response('{}', [], 503));

        try {
            Authsignal::getUser(['userId' => 'user']);
        } catch (AuthsignalApiError $error) {
            // Expected.
        }

        $this->assertEquals(1, $this->requestCount() - $before);
    }
}
