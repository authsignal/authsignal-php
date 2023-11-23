
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

use donatj\MockWebServer\MockWebServer;
use donatj\MockWebServer\Response;

use Firebase\JWT\JWT;

class AuthsignalTest extends PHPUnit\Framework\TestCase {
    /** @var MockWebServer */
	protected static $server;

    public static function setUpBeforeClass(): void {
        Authsignal::setApiKey('secret');
        self::$server = new MockWebServer;
		self::$server->start();

        Authsignal::setApiHostname(self::$server->getServerRoot());
    }

    static function tearDownAfterClass(): void {
		self::$server->stop();
	}

    public function testSetApiKey()
    {
        $this->assertEquals('secret', Authsignal::getApiKey());
    }

    public function testTrackAction() {
        // Mock response
        $mockedResponse = array("state" => "ALLOW",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "ruleIds" => []);

        self::$server->setResponseOfPath('/v1/users/123%3Atest/actions/signIn', new Response(json_encode($mockedResponse)));

        $payload = array(
            "redirectUrl" => "https://www.yourapp.com/back_to_your_app",
            "email" => "test@email",
            "deviceId" => "123",
            "userAgent" => "Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion",
            "ipAddress" => "1.1.1.1",
            "custom" => array(
              "yourCustomBoolean" => true,
              "yourCustomString" => true,
              "yourCustomNumber" => 1.12
            ));

        $response = Authsignal::track(userId: "123:test",
                                            action: "signIn",
                                            payload: $payload);

        $this->assertEquals($response["state"], "ALLOW");
        $this->assertEquals($response["idempotencyKey"], $mockedResponse["idempotencyKey"]);
    }

    public function testgetAction() {
        // Mock response
        $mockedResponse = array("state" => "ALLOW",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "stateUpdatedAt" => "2022-07-25T03:19:00.316Z",
              "createdAt" => "2022-07-25T03:19:00.316Z",
              "ruleIds" => []);

        self::$server->setResponseOfPath("/v1/users/123%3Atest/actions/signIn/5924a649-b5d3-4baf-a4ab-4b812dde97a04", new Response(json_encode($mockedResponse)));

        $response = Authsignal::getAction(userId: "123:test",
                                            action: "signIn",
                                            idempotencyKey: "5924a649-b5d3-4baf-a4ab-4b812dde97a04");

        $this->assertEquals($response["state"], "ALLOW");
        $this->assertEquals($response["idempotencyKey"], $mockedResponse["idempotencyKey"]);
        $this->assertEquals($response["stateUpdatedAt"], $mockedResponse["stateUpdatedAt"]);
    }

    public function testgetUser() {
        $mockedResponse = array("isEnrolled" => false,
              "accessToken" => "xxxx",
              "url" => "wwwww");

        self::$server->setResponseOfPath("/v1/users/123%3Atest", new Response(json_encode($mockedResponse)));
        $response = Authsignal::getUser(userId: "123:test", redirectUrl: "https://www.example.com/");
        
        $this->assertEquals($response["isEnrolled"], $mockedResponse["isEnrolled"]);
        $this->assertEquals($response["url"], $mockedResponse["url"]);
    }   

    public function testEnrollVerifiedAuthenticator() {
        $mockedResponse = array(
            "authenticator" => array(
                "userAuthenticatorId" => "9b2cfd40-7df2-4658-852d-a0c3456e5a2e",
                "authenticatorType" => "OOB",
                "isDefault" => true,
                "phoneNumber"=> "+6427000000",
                "createdAt"=> "2022-07-25T03:31:36.219Z",
                "oobChannel"=> "SMS"));

        self::$server->setResponseOfPath("/v1/users/123%3Atest/authenticators", new Response(json_encode($mockedResponse)));

        $response = Authsignal::enrollVerifiedAuthenticator(userId: "123:test",
                                                   authenticator: array("oobChannel" => "SMS"
                                                                ,"phoneNumber" => "+6427000000"));
        
        $this->assertEquals($response["authenticator"]["userAuthenticatorId"], $mockedResponse["authenticator"]["userAuthenticatorId"]);
    }

    public function testValidateChallenge() {
        $mockedResponse = array("state" => "CHALLENGE_SUCCEEDED",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "stateUpdatedAt" => "2022-07-25T03:19:00.316Z",
              "createdAt" => "2022-07-25T03:19:00.316Z",
              "ruleIds" => []);

        self::$server->setResponseOfPath("/v1/users/123%3Atest/actions/signIn/5924a649-b5d3-4baf-a4ab-4b812dde97a0", new Response(json_encode($mockedResponse)));

        $key = "secret";
        $testTokenPayload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => 1357000000,
            'other' => [
                'userId' => "123:test",
                'state' => "CHALLENGE_SUCCEEDED",
                'action' => 'signIn',
                'idempotencyKey' => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
            ]
        ];
        $token = JWT::encode($testTokenPayload, $key, 'HS256');

        $response = Authsignal::validateChallenge(userId: "123:test", token: $token);

        $this->assertEquals($response["success"], true);
    }

    public function testValidateChallengeOptionalUserId() {
        $mockedResponse = array("state" => "CHALLENGE_SUCCEEDED",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "stateUpdatedAt" => "2022-07-25T03:19:00.316Z",
              "createdAt" => "2022-07-25T03:19:00.316Z",
              "ruleIds" => []);

        self::$server->setResponseOfPath("/v1/users/123%3Atest/actions/signIn/5924a649-b5d3-4baf-a4ab-4b812dde97a0", new Response(json_encode($mockedResponse)));

        $key = "secret";
        $testTokenPayload = [
            'iss' => 'http://example.org',
            'aud' => 'http://example.com',
            'iat' => 1356999524,
            'nbf' => 1357000000,
            'other' => [
                'userId' => "123:test",
                'state' => "CHALLENGE_SUCCEEDED",
                'action' => 'signIn',
                'idempotencyKey' => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
            ]
        ];
        $token = JWT::encode($testTokenPayload, $key, 'HS256');

        $response = Authsignal::validateChallenge(token: $token);

        $this->assertEquals($response["success"], true);
    }
}