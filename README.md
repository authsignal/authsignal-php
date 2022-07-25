# Authsignal Server PHP SDK

[Authsignal](https://www.authsignal.com/?utm_source=github&utm_medium=php_sdk) provides passwordless step up authentication (Multi-factor Authentication - MFA) that can be placed anywhere within your application. Authsignal also provides a no-code fraud risk rules engine to manage when step up challenges are triggered.

## Installation

1. Add Authsignal's library as a depependency in composer.json

```php
"require": {
    ...
    "authsignal/authsignal-php" : "0.1.2"
    ...
}
```

2. Run composer update.
3. Now Authsignal will be autoloaded into your project.

## Configuration
Initialize the Authsignal SDK, ensuring you do not hard code the Authsignal Secret Key, always keep this safe.

```php
Authsignal::setApiKey('secret');
```

## Usage

Authsignal's server side signal API has four main calls `trackAction`, `getAction`, `getUser`, `identify` and `enrolAuthenticator`

### Track Action
The track action call is the main api call to send actions to authsignal, the default decision is to `ALLOW` actions, this allows you to call track action as a means to keep an audit trail of your user activity.

Add to the rules in the admin portal or the change default decision to influence the flows for your end users. If a user is not enrolled with authenticators, the default decision is to `ALLOW`.

```php
# OPTIONAL: The Authsignal cookie available when using the authsignal browser Javascript SDK
# you could you use own device/session/fingerprinting identifiers.
$authsignalCookie = $_COOKIE["__as_aid"];

# OPTIONAL: The idempotencyKey is a unique identifier per track action
# this could be for a unique object associated to your application
# like a shopping cart check out id
# If ommitted, Authsignal will generate the idempotencyKey and return in the response
$idempotencyKey = "XXXX-XXXX";

# OPTIONAL: If you're using a redirect flow, set the redirect URL, this is the url authsignal will redirect to after a Challenge is completed.
$redirectUrl = "https://www.yourapp.com/back_to_your_app";

# Use the appropriate headers to get the true ip address of your user
$ipAddress = $_SERVER['HTTP_X_FORWARDED_FOR'] || $_SERVER['HTTP_X_REAL_IP'] ||  $_SERVER['REMOTE_ADDR'];

$payload = array(
            "redirectUrl" => $redirectUrl,
            "email" => "test@email",
            "deviceId" => $authsignalCookie,
            "userAgent" => $_SERVER["HTTP_USER_AGENT"],
            "ipAddress" => $ipAddress,
            "custom" => array(
              "yourCustomBoolean" => true,
              "yourCustomString" => true,
              "yourCustomNumber" => 1.12
            ));

$response = Authsignal::trackAction(userId: "123345",
                                    actionCode: "signIn",
                                    payload: $payload);
```

*Response*
```php
$response = Authsignal::trackAction(...)

switch ($response["state"]) {
    case "ALLOW":
        // Carry on with your operation/business logic
        break;
    case "BLOCK":
        // Stop your operations
        break;
    case "CHALLENGE_REQUIRED":
        // Step up authentication required, redirect or pass the challengeUrl to the front end
        $response["challengeUrl"];
        break;
}
```

### Get Action
Call get action after a challenge is completed by the user, after a redirect or a succesful browser challenge pop-up flow, and if the state of the action is `CHALLENGE_SUCCEEDED` you can proceed with completing the business logic.

```php
$response = Authsignal::getAction(userId: "123",
                                actionCode: "signIn",
                                idempotencyKey: "2320ce18-91be-47a8-9bbf-eec642807c34");

if($response["state"] === "CHALLENGE_SUCCEEDED"){
// The user has successfully completed the challenge, and you should proceed with
// the business logic
}
```

### Get User
Get user retrieves the current enrolment state of the user, use this call to redirect users to the enrolment or management flows so that the user can do self service management of their authenticator factors. User the `url` in the response to either redirect or initiate the pop up client side flow.

```php
$response = Authsignal::getUser(userId: "123", redirectUrl: "https://www.example.com/");

$isEnrolled = $response["isEnrolled"];
$url = $response["isEnrolled"];
```

### Identify
Get identify to link and update additional user indetifiers (like email) to the primary record.

```php
$response = Authsignal::identify(userId: "123", user: array("email" => "email@email.com"));
```

### Enrol Authenticator
If your application already has a valid authenticator like a validated phone number for your customer, you can enrol the authenticator on behalf of the user using this function

```php
$response = Authsignal::enrolAuthenticator(userId: "123",
                                            authenticator: array("oobChannel" => "SMS"
                                                        ,"phoneNumber" => "+64270000000"));
```

## License

The library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
