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

    public function testGetUser() {
        $mockedResponse = array("isEnrolled" => false,
              "accessToken" => "xxxx",
              "url" => "wwwww");

        self::$server->setResponseOfPath("/v1/users/123%3Atest", new Response(json_encode($mockedResponse)));

        $params = array(
            "userId" => "123:test",
            "redirectUrl" => "https://www.example.com/"
        );

        $response = Authsignal::getUser($params);
        
        $this->assertEquals($response["isEnrolled"], $mockedResponse["isEnrolled"]);
        $this->assertEquals($response["url"], $mockedResponse["url"]);
    }

    public function testUpdateUser() {
        $mockedResponse = array(
            "userId" => "550e8400-e29b-41d4-a716-446655440000",
            "email" => "updated_email",
        );
    
        self::$server->setResponseOfPath("/v1/users/550e8400-e29b-41d4-a716-446655440000", new Response(json_encode($mockedResponse)));
    
        $params = array(
            "userId" => "550e8400-e29b-41d4-a716-446655440000",
            "attributes" => array(
                "email" => "updated_email",
            )
        );
    
        $response = Authsignal::updateUser($params);
    
        $this->assertEquals($response["userId"], $mockedResponse["userId"]);
        $this->assertEquals($response["email"], $mockedResponse["email"]);
    }

    public function testDeleteUser() {
        $mockedResponse = array("success" => true);
    
        self::$server->setResponseOfPath("/v1/users/1234", new Response(json_encode($mockedResponse), [], 200));
    
        $params = array("userId" => "1234");
        $response = Authsignal::deleteUser($params);
    
        $this->assertEquals($response["success"], true);
    }

    public function testGetAuthenticators() {
        $mockedResponse = array(
            array(
                "userAuthenticatorId" => "authenticator_id_1",
                "authenticatorType" => "SMS",
                "isDefault" => true,
                "phoneNumber" => "+6427000000"
            ),
            array(
                "userAuthenticatorId" => "authenticator_id_2",
                "authenticatorType" => "EMAIL",
                "isDefault" => false,
                "email" => "user@example.com"
            )
        );

        self::$server->setResponseOfPath("/v1/users/123%3Atest/authenticators", new Response(json_encode($mockedResponse)));

        $params = array(
            "userId" => "123:test"
        );

        $response = Authsignal::getAuthenticators($params);

        $this->assertIsArray($response);
        $this->assertCount(2, $response);
        $this->assertEquals($response[0]["userAuthenticatorId"], $mockedResponse[0]["userAuthenticatorId"]);
        $this->assertEquals($response[1]["userAuthenticatorId"], $mockedResponse[1]["userAuthenticatorId"]);
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

        $params = array(
            "userId" => "123:test",
            "attributes" => array(
                "oobChannel" => "SMS",
                "phoneNumber" => "+6427000000"
            )
        );

        $response = Authsignal::enrollVerifiedAuthenticator($params);
        
        $this->assertEquals($response["authenticator"]["userAuthenticatorId"], $mockedResponse["authenticator"]["userAuthenticatorId"]);
    }

    public function testDeleteAuthenticator() {
        $mockedResponse = array("success" => true);
    
        self::$server->setResponseOfPath("/v1/users/123%3Atest/authenticators/456%3Atest", new Response(json_encode($mockedResponse), [], 200));
    
        $params = array(
            "userId" => "123:test",
            "userAuthenticatorId" => "456:test"
        );
        $response = Authsignal::deleteAuthenticator($params);
    
        $this->assertArrayHasKey("success", $response);
        $this->assertEquals($response["success"], true);
    }

    public function testTrackAction() {
        // Mock response
        $mockedResponse = array("state" => "ALLOW",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "ruleIds" => []);

        self::$server->setResponseOfPath('/v1/users/123%3Atest/actions/signIn', new Response(json_encode($mockedResponse)));

        $params = array(
            "userId" => "123:test",
            "action" => "signIn",
            "attributes" => array(
                "redirectUrl" => "https://www.yourapp.com/back_to_your_app",
                "email" => "test@email",
                "deviceId" => "123",
                "userAgent" => "Mozilla/5.0 (platform; rv:geckoversion) Gecko/geckotrail Firefox/firefoxversion",
                "ipAddress" => "1.1.1.1",
                "custom" => array(
                    "yourCustomBoolean" => true,
                    "yourCustomString" => true,
                    "yourCustomNumber" => 1.12
                )
            )
        );

        $response = Authsignal::track($params);

        $this->assertEquals($response["state"], "ALLOW");
        $this->assertEquals($response["idempotencyKey"], $mockedResponse["idempotencyKey"]);
    }

    public function testValidateChallenge() {
        $mockedResponse = array("state" => "CHALLENGE_SUCCEEDED",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "stateUpdatedAt" => "2022-07-25T03:19:00.316Z",
              "userId" => "123:test",
              "isValid" => "true",
              "action" => "signIn",
              "verificationMethod" => "AUTHENTICATOR_APP");

        self::$server->setResponseOfPath("/v1/validate", new Response(json_encode($mockedResponse)));

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

        $params = array(
            "userId" => "123:test",
            "token" => $token
        );

        $response = Authsignal::validateChallenge($params);

        $this->assertEquals($response['isValid'], "true");
    }

    public function testGetAction() {
        // Mock response
        $mockedResponse = array("state" => "ALLOW",
              "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
              "stateUpdatedAt" => "2022-07-25T03:19:00.316Z",
              "createdAt" => "2022-07-25T03:19:00.316Z",
              "ruleIds" => []);

        self::$server->setResponseOfPath("/v1/users/123%3Atest/actions/signIn/5924a649-b5d3-4baf-a4ab-4b812dde97a04", new Response(json_encode($mockedResponse)));

        $params = array(
            "userId" => "123:test",
            "action" => "signIn",
            "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a04"
        );

        $response = Authsignal::getAction($params);

        $this->assertEquals($response["state"], "ALLOW");
        $this->assertEquals($response["idempotencyKey"], $mockedResponse["idempotencyKey"]);
        $this->assertEquals($response["stateUpdatedAt"], $mockedResponse["stateUpdatedAt"]);
    }

    public function testUpdateAction() {
        $mockedResponse = array(
            "userId" => "123:test",
            "action" => "signIn",
            "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
            "state" => "CHALLENGE_FAILED"
        );

        self::$server->setResponseOfPath("/v1/users/123%3Atest/actions/signIn/5924a649-b5d3-4baf-a4ab-4b812dde97a0", new Response(json_encode($mockedResponse)));

        $params = array(
            "userId" => "123:test",
            "action" => "signIn",
            "idempotencyKey" => "5924a649-b5d3-4baf-a4ab-4b812dde97a0",
            "attributes" => array("state" => "CHALLENGE_FAILED")
        );

        $response = Authsignal::updateAction($params);

        $this->assertEquals($response["userId"], $mockedResponse["userId"]);
        $this->assertEquals($response["action"], $mockedResponse["action"]);
        $this->assertEquals($response["idempotencyKey"], $mockedResponse["idempotencyKey"]);
        $this->assertEquals($response["state"], $mockedResponse["state"]);
    }
}