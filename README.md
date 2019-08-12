# MemberClicks provider for OAuth 2.0 Client

This package provides MemberClicks OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

## Installation

To install, use composer:

```
composer require knucklepuck/oauth2-memberclicks
```

## Prerequirements

1) [MemberClicks API Client](https://help.memberclicks.com/hc/en-us/articles/230536267-API-Management) configured.

## Usage

Usage is the same as The League's OAuth client, using `\Knucklepuck\OAuth2\Client\Provider\MemberClicks` as the provider.

### Authorization Code Flow

```php
$provider = new Knucklepuck\OAuth2\Client\Provider\MemberClicks([
    'clientId'          => '{MemberClicks-client-id}',
    'clientSecret'      => '{MemberClicks-client-secret}',
    'redirectUri'       => 'https://example.com/callback-url',
    'domain'            => 'https://<orgId>.memberclicks.net',
]);

if (!isset($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: '.$authUrl);
    exit;

// Check given state against previously stored one to mitigate CSRF attack
} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'redirect_uri' => 'https://example.com/callback-url',
        'code' => $_GET['code']
    ]);

    // Optional: Now you have a token you can look up a users profile data
    try {

        // We got an access token, let's now get the user's details
        $user = $provider->getResourceOwner($token);

        // Use these details to create a new profile
        printf('Hello %s!', $user->getId());

    } catch (Exception $e) {

        // Failed to get user details
        exit('Oh dear...');
    }

    // Use this to interact with an API on the users behalf
    echo $token->getToken();
}
```

## Credits

- [Knucklepuck](https://github.com/knucklepuck)
- [Joey Blake](https://github.com/joeyblake)
