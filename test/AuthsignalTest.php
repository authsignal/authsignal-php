
<?php

require_once dirname(__DIR__) . '/vendor/autoload.php';

class AuthsignalTest extends PHPUnit\Framework\TestCase {

    public static function setUpBeforeClass(): void {
        Authsignal::setApiKey('2s+2kWC083rKOdGxUaVPEvzGsn+cwtZdSRgWWTeEhFGWea29kDcLfA==');
        //Authsignal::setApiHostname('http://localhost:8080');
        Authsignal::setApiHostname('https://dev-signal.authsignal.com');
    }

    public function testSetApiKey(){
        $this->assertEquals('2s+2kWC083rKOdGxUaVPEvzGsn+cwtZdSRgWWTeEhFGWea29kDcLfA==', Authsignal::getApiKey());
    }

    public function testTrackAction() {
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

        $response = Authsignal::trackAction(userId: "123:test",
                                            actionCode: "signIn",
                                            payload: $payload);

        print_r($response);
    }

    public function testgetAction() {
        $response = Authsignal::getAction(userId: "123:test",
                                            actionCode: "signIn",
                                            idempotencyKey: "2320ce18-91be-47a8-9bbf-eec642807c34");
    }

    public function testgetUser() {
        $response = Authsignal::getUser(userId: "123:test", redirectUrl: "https://www.example.com/");
    }

    public function testIdentify() {
        $response = Authsignal::getUser(userId: "123:test", redirectUrl: "https://www.example.com/");
    }

    public function testEnrolAuthenticator() {
        $response = Authsignal::enrolAuthenticator(userId: "123:test",
                                                   authenticator: array("oobChannel" => "SMS"
                                                                ,"phoneNumber" => "+64273330770"));
    }
}