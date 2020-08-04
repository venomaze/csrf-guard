const express = require('express');
const session = require('express-session');

const CSRFGuard = require('../src');

const app = express();

app.use(
  session({
    secret: 'secret_key',
  })
);

app.use(express.urlencoded());
app.use(express.json());

app.use(
  new CSRFGuard({
    secret: 'secret_key',
  })
);

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

app.post('/test', (req, res) => {
  const isTokenValid = req.isTokenValid();
  const message = isTokenValid ? 'The token is valid.' : 'Token is NOT valid.';

  res.send(message);
});

app.listen(3000, () => {
  console.log('Server running on port 3000');
});
