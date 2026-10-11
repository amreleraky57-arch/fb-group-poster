
'use strict';

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const authenticate = require('./authenticate');

const app = express();
const port = Number(process.env.PORT) || 8000;

const USER_EMAIL = process.env.USER_EMAIL;
const USER_PASS = process.env.USER_PASS;
const SECRET = process.env.SECRET;

app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));

// Health check: verifies that the application is running.
app.get('/', (_req, res) => {
  res.status(200).send('ready');
});

// Readiness check: verifies that required configuration exists.
app.get('/health', (_req, res) => {
  const configured = Boolean(
    SECRET && USER_EMAIL && USER_PASS
  );

  res.status(configured ? 200 : 503).json({
    status: configured ? 'ready' : 'missing_configuration'
  });
});

// Accept a signed request containing the post text and group ID.
app.post('/', (req, res) => {
  if (!SECRET || !USER_EMAIL || !USER_PASS) {
    return res.status(503).json({
      status: 'error',
      message: 'Application configuration is incomplete.'
    });
  }

  const signedMessage = req.body && req.body.signed;

  if (
    typeof signedMessage !== 'string' ||
    signedMessage.length === 0
  ) {
    return res.status(400).json({
      status: 'error',
      message: 'A signed JWT is required.'
    });
  }

  let message;

  try {
    message = jwt.verify(signedMessage, SECRET, {
      algorithms: ['HS256']
    });
  } catch (_error) {
    return res.status(401).json({
      status: 'error',
      message: 'Invalid or expired signature.'
    });
  }

  const msg = message.text;
  const groupId = message.groupId;

  if (
    typeof msg !== 'string' ||
    msg.trim().length === 0 ||
    msg.length > 5000 ||
    typeof groupId !== 'string' ||
    !/^\d{5,30}$/.test(groupId)
  ) {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid post text or group ID.'
    });
  }

  // The legacy Selenium publisher is not verified against
  // Facebook's current interface. Do not report success
  // until the publisher confirms the outcome.
  try {
    authenticate(
      USER_EMAIL,
      USER_PASS,
      { msg, groupId },
      (err, result) => {
        if (err || !result) {
          console.error('Publisher initialization failed.');
          return;
        }

        // This callback does not necessarily prove that
        // Facebook accepted or published the post.
        if (typeof result.kill === 'function') {
          setTimeout(() => {
            try {
              result.kill();
            } catch (_error) {
              console.error('Publisher cleanup failed.');
            }
          }, 10000);
        }
      }
    );
  } catch (_error) {
    console.error('Publisher could not be started.');

    return res.status(500).json({
      status: 'error',
      message: 'Publisher could not be started.'
    });
  }

  return res.status(202).json({
    status: 'accepted',
    message:
      'Request accepted for processing; publication is not confirmed.'
  });
});

// Handle malformed JSON and unexpected request errors.
app.use((err, _req, res, _next) => {
  if (err && err.type === 'entity.parse.failed') {
    return res.status(400).json({
      status: 'error',
      message: 'Invalid JSON.'
    });
  }

  console.error('Request processing error.');

  return res.status(500).json({
    status: 'error',
    message: 'Internal server error.'
  });
});

app.listen(port, () => {
  console.log(`Application listening on port ${port}.`);
});
