# csrf-guard

> Simple Anti-CSRF Token implementation for Express applications.

This package only uses Node.js native [crypto](https://nodejs.org/api/crypto.html) module and no other dependency.
I did my best to follow [OWASP CSRF token best practices](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).
Now it's your responsibilty to follow best practices for session management. I do recommend you read [this](https://blog.jscrambler.com/best-practices-for-secure-session-management-in-node/) article before anything else.

**Disclaimer**: This package is still under development, I do NOT recommend using it for production yet.

## Installation

**npm**:

```
npm install csrf-guard
```

**yarn**:

```
yarn add csrf-guard
```

**GitHub**:

```
git clone https://github.com/venomaze/csrf-guard.git
```

## Usage

First register the middleware:

```js
const express = require('express');
const session = require('session');
const CSRFGuard = require('csrf-guard');

const app = express();

// DO NOT USE SESSION LIKE THIS!
app.use(
  session({
    secret: 'secret_key',
  })
);

app.use(
  new CSRFGuard({
    secret: 'secret_key', // Secret key is required
  })
);
```

Then you have access to two `getToken` and `isTokenValid` methods from request object.

1. Generating a token (Remember you have to use csrf_token name for the token):

```js
app.get('/', async (req, res) => {
  const token = await req.getToken();
  const form = `
    <form action="/test" method="POST">
      <input type="hidden" name="csrf_token" value="${token}" />
      <input type="text" name="username" />
      <input type="submit" />
    </form>
  `;

  res.send(form);
});
```

2. Validating the token:

```js
app.post('/test', (req, res) => {
  const isTokenValid = req.isTokenValid();
  const message = isTokenValid ? 'The token is valid.' : 'Token is NOT valid.';

  res.send(message);
});
```

## Token generation methods

We have to options, the first one is **Synchronizer Token Pattern** and the second one is **HMAC Based Token Pattern**. You can read more about them [here](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html).

### Synchronizer Token Pattern

To be able to use this method, you have to set `synchronizer` to `true` in options object. With this method you have access to `forced` mode which generates a new token even if there is one already. This is the default method.  
**Setting up**:

```js
app.use(
  new CSRFGuard({
    secret: 'secret_key',
    synchronizer: true,
  })
);
```

**Generating token**:

```js
const token = await req.getToken(true); // Forced is set to true. This way you'll get a new token per request. (Default to false)
```

### HMAC Based Token Pattern

To be able to use this method, you have to set `synchronizer` to `false` in options object. With this method you have access to `expiryTime` option which gives you this possibility to expire tokens even if the session id isn't changed. By default, tokens won't be expired until the session is regenerated.  
**Setting up**:

```js
app.use(
  new CSRFGuard({
    secret: 'secret_key',
    synchronizer: false,
    expiryTime: 5000, // Tokens will be expired after 5 seconds
  })
);
```

**Generating token**:

```js
const token = req.getToken();
```
