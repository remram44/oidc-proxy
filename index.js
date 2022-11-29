const express = require('express');
const { auth, requiresAuth } = require('express-openid-connect');
const fs = require('fs');
const http = require('http');
const https = require('https');
const httpProxy = require('http-proxy');
const proxy = httpProxy.createProxyServer();

const PORT = 3000;

const app = express();

const config = {
  authRequired: false,
  auth0Logout: true,
  baseURL: process.env.BASE_URL,
  secret: process.env.SECRET,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  issuerBaseURL: process.env.ISSUER_BASE_URL,
  routes: {
    callback: '/oauth2/callback',
    login: '/oauth2/login',
    logout: '/oauth2/logout',
    postLogoutRedirect: '/',
  },
  authorizationParams: {
    scope: 'openid profile email',
    response_type: 'code',
  },
};

const ACCESS_FILE = process.env.ACCESS_FILE;

function listsDiffer(a, b) {
  if(a.length != b.length) {
    return true;
  }
  for(let i = 0; i < a.length; ++i) {
    if(a[i] != b[i]) {
      return true;
    }
  }
  return false;
}

let allowedUsers = [];
let bypassTokens = [];
function loadAllowedUsers() {
  fs.readFile(ACCESS_FILE, 'utf8', (err, data) => {
    if(err) {
      console.error(err);
      process.exit(1);
    }

    // Load the list
    const loadedUsers = [];
    const loadedTokens = [];
    for(let line of data.split('\n')) {
      line = line.trim();
      if(line.length > 0 && line[0] != '#') {
        if(line[0] == '%') {
          loadedTokens.push(line.substring(1));
        } else {
          loadedUsers.push(line);
        }
      }
    }

    // Log if the list has changed
    if(listsDiffer(allowedUsers, loadedUsers)
    || listsDiffer(bypassTokens, loadedTokens)) {
      console.log('Loaded new users list');
    }

    // Update global and reset timer
    allowedUsers = loadedUsers;
    bypassTokens = loadedTokens;
    setTimeout(loadAllowedUsers, 30000);
  });
}
loadAllowedUsers();

const upstream_url = new URL(process.env.UPSTREAM);
let UPSTREAM_PROTO, UPSTREAM_PORT;
if(upstream_url.protocol === 'http:') {
  UPSTREAM_PROTO = http;
  UPSTREAM_PORT = 80;
} else if(upstream_url.protocol === 'https:') {
  UPSTREAM_PROTO = https;
  UPSTREAM_PORT = 443;
} else {
  console.error('Invalid UPSTREAM: protocol should be http or https');
  process.exit(1);
}
if(
  (upstream_url.pathname !== '/' && upstream_url.pathname !== '')
  || upstream_url.search
  || upstream_url.hash
  || upstream_url.username
  || upstream_url.password
) {
  console.error('Invalid UPSTREAM: path is set');
  process.exit(1);
}
const UPSTREAM_HOST = upstream_url.hostname;
if(upstream_url.port) {
  UPSTREAM_PORT = parseInt(upstream_url.port);
}
console.log(`Using upstream ${UPSTREAM_HOST}:${UPSTREAM_PORT}`);

app.use(auth(config));

app.all('/*', (req, res) => {
  // Check bypass token, then OIDC login
  if(req.headers['x-oidc-proxy-bypass']) {
    // Token is set, check it
    if(bypassTokens.indexOf(req.headers['x-oidc-proxy-bypass']) === -1) {
      // Bad token
      res.sendStatus(403);
      return;
    }
  } else if(!req.oidc.isAuthenticated()) {
    // Not authenticated, send login form or error
    if(req.accepts('html')) {
      return res.oidc.login();
    } else {
      res.sendStatus(403);
      return;
    }
  } else if(allowedUsers.indexOf(req.oidc.user.sub) == -1) {
    // Unauthorized user, reject
    res.sendStatus(403);
    return;
  }

  // Otherwise, proxy
  proxy.web(req, res, {target: upstream_url});
});

const server = http.createServer(app);
server.on('upgrade', (req, socket, head) => {
  proxy.ws(req, socket, head, {target: upstream_url});
});

server.listen(PORT, () => {
  console.log(`app listening on port ${PORT}`);
});
