# Authsignal Server PHP SDK

Check out our [official PHP SDK documentation](https://docs.authsignal.com/sdks/server/php).

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

## Initialization

Initialize the Authsignal SDK, ensuring you do not hard code the Authsignal Secret Key, always keep this safe.

```php
Authsignal::setApiKey('secretKey');
```

You can find your `secretKey` in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

## Region selection

Authsignal has multiple api hosting regions. To view your hostname for your tenant, find it in the [Authsignal Portal](https://portal.authsignal.com/organisations/tenants/api).

| Region      | Base URL                               |
| ----------- | -------------------------------------- |
| US (Oregon) | https://challenge.authsignal.com/v1    |
| AU (Sydney) | https://au-challenge.authsignal.com/v1 |
| EU (Dublin) | https://eu-challenge.authsignal.com/v1 |

You can set the hostname via the following code. If the `setApiHostname` function is not called, the api call defaults to the main Authsignal US region hostname `https://signal.authsignal.com`

An example setting the client to use the AU region.

```php
Authsignal::setApiHostname("https://au.signal.authsignal.com");
```

Alternatively, an environment variable can be used to set the base URL:

```bash
AUTHSIGNAL_SERVER_API_ENDPOINT=https://au.signal.authsignal.com/v1
```

## Usage

Authsignal's server side signal API has four main calls `trackAction`, `getAction`, `getUser`, `enrolAuthenticator`

For more details on these api calls, refer to our [official PHP SDK docs](https://docs.authsignal.com/sdks/server/php#trackaction).

## License

The library is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
