const fs = require('fs');
const nodemailer = require("nodemailer");
const url = require('url');
const querystring = require('querystring');
const path = require('path');
const crypto = require('crypto');

class PauthBuilder {

  loginPagePath(path) {
    this._loginPagePath = path;
    return this;
  }

  ownerEmail(email) {
    this._ownerEmail = email;
    return this;
  }

  async build() {

    const authDir = path.join('.gemdrive', 'auth');
    await fs.promises.mkdir(authDir, { recursive: true });

    const gemAuthDir = path.join('gemdrive', 'auth', 'acls');
    await fs.promises.mkdir(gemAuthDir, { recursive: true });

    const tokensPath = path.join(authDir, 'tokens.json');

    let tokens;
    try {
      const tokensText = await fs.promises.readFile(tokensPath);
      tokens = JSON.parse(tokensText);
    }
    catch (e) {
      tokens = {};
      await persistJson(tokens, tokensPath);
    }

    const configPath = 'gemdrive_config.json';

    let config;
    try {
      const configText = await fs.promises.readFile(configPath);
      config = JSON.parse(configText);
    }
    catch (e) {
      throw new Error("No config provided");
    }

    return new Pauth(config, tokens, this._loginPagePath, this._ownerEmail);
  }
}

class Pauth {

  constructor(config, tokens, loginPagePath, ownerEmail) {
    this._authDir = path.join('.gemdrive', 'auth');
    this._gemAuthDir = path.join('gemdrive', 'auth');
    this._config = config;
    this._tokens = tokens;
    this._persistTokens();
    this._loginPagePath = loginPagePath ? loginPagePath : path.join(__dirname, 'login.html');
    this._ownerEmail = ownerEmail ? ownerEmail : '';

    this._pendingVerifications = {};

    this._emailer = nodemailer.createTransport({
      host: config.smtp.server,
      port: config.smtp.port,
      secure: false, // true for 465, false for other ports
      auth: {
        user: config.smtp.username,
        pass: config.smtp.password,
      }
    });

    // periodically delete expired tokens
    const TEN_MIN_MS = 10*60*1000;
    setInterval(() => {
      for (const key in this._tokens) {
        const token = this._tokens[key];

        if (token.expiresAt !== undefined) {
          const timestamp = new Date();
          const expireTime = new Date(Date.parse(token.expiresAt));
          if (timestamp > expireTime) {
            delete this._tokens[key];
            this._persistTokens();
          }
        }
      }
    }, TEN_MIN_MS);
  }

  async handle(req, res, reqPath, rootPath, token) {

    res.setHeader('X-Frame-Options', 'SAMEORIGIN');

    const u = url.parse(req.url); 
    const params = querystring.parse(u.query);

    let method;
    if (reqPath.endsWith('.gemdrive-acl.tsv') && req.method === 'PUT') {
      method = 'setAcl';
    }
    else if (reqPath === '/.gemdrive/auth/requestPerms') {
      method = 'requestPerms';
    }
    else if (reqPath.endsWith('/auth/delegate')) {
      method = 'delegate';
    }
    else {
      method = params['pauth-method'];
    }

    if (method === 'login') {
      try {

        const authReq = {
          email: params.email,
          perms: {
            '/': {
              own: true,
            },
          },
        };

        const keys = await this.authorize(authReq);
        const newToken = keys.tokenKey;
        const cookieTokenKey = keys.cookieTokenKey;
        res.setHeader('Set-Cookie', `access_token=${cookieTokenKey}; SameSite=Lax; Max-Age=259200; Secure; HttpOnly`);
        if (newToken === null) {
          res.write("User does not have permissions to do that");
        }
        else {
          res.write(newToken);
        }
      }
      catch (e) {
        console.error(e);
        res.statusCode = 400;
        res.write("Authorization failed");
        res.end();
        return;
      }

      res.end();
    }
    else if (method === 'verify') {
      const success = this.verify(params.key);
      if (success) {
        res.write("Verification succeeded. You can close this tab and return to your previous session.");
      }
      else {
        res.write("Verification failed. It may have expired.");
      }

      res.end();
    }
    else if (method === 'authorize') {

      let filePath;
      // TODO: canOwn root indicates this is an "identity token", ie all powers
      // for the given user. It's a bit of a hack
      const pathParts = parsePath(reqPath);
      const tokenPerms = this._getTokenPerms(token, pathParts);
      if (!tokenPerms || !(tokenPerms.own === true)) {
        filePath = this._loginPagePath;
        const stat = await fs.promises.stat(filePath);

        res.writeHead(403, {
          'Content-Type': 'text/html',
          'Content-Length': stat.size,
        });

        const f = fs.createReadStream(filePath);
        f.pipe(res);
      }
      else {

        if (!params.redirect_uri.startsWith(params.client_id)) {
          res.write("Invalid redirect_uri. Not safe to send you back to the app");
          res.end();
          return;
        }

        const requestedPerms = parsePermsFromScope(params.scope);
        const hasPerms = await this.tokenHasPerms(token, requestedPerms);

        if (hasPerms) {
          filePath = path.join(__dirname, 'authorize.html');
          const stat = await fs.promises.stat(filePath);

          res.writeHead(200, {
            'Content-Type': 'text/html',
            'Content-Length': stat.size,
          });

          const f = fs.createReadStream(filePath);
          f.pipe(res);
        }
        else {
          filePath = path.join(__dirname, 'request_access.html');
          const stat = await fs.promises.stat(filePath);

          res.writeHead(403, {
            'Content-Type': 'text/html',
            'Content-Length': stat.size,
          });

          const f = fs.createReadStream(filePath);
          f.pipe(res);
        }
      }
    }
    else if (method === 'delegate' && req.method === 'POST') {

      const body = await parseBody(req);
      const permRequest = JSON.parse(body);
      const accessTokenKey = await this.delegate(token, permRequest);

      if (!accessTokenKey) {
        res.statusCode = 403;
        res.write("Delegation error");
      }
      else {
        res.write(accessTokenKey);
      }

      res.end();
    }
    else if (method === 'delegate-auth-code' && req.method === 'POST') {
      const perms = parsePermsFromScope(params.scope);
      const authCode = await this.delegateAuthCode(
        token, params['code_challenge'], params['client_id'],
        params['redirect_uri'], { perms });

      if (authCode) {
        res.write(authCode);
      }
      else {
        res.write("User doesn't have permission to do that");
      }

      res.end();
    }
    else if (method === 'token') {

      const body = await parseBody(req);
      const params = querystring.parse(body);

      const grantType = params['grant_type'];


      const authCode = params['code'];
      const authToken = this._tokens[authCode];

      if (!authCode) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify({
          error: "invalid_request",
          error_description: "Missing code",
        }));
      }
      else if (grantType !== 'authorization_code') {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify({
          error: "invalid_request",
          error_description: "Invalid grant_type. Must be authorization_code",
        }));
      }
      else if (!authToken) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify({
          error: "invalid_grant",
          error_description: "No auth token found. Maybe it expired",
        }));
      }
      else if (!params['client_id'] || (params['client_id'] !== authToken.clientId)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify({
          error: "invalid_client",
          error_description: "client_id doesn't match",
        }));
      }
      else if (!params['redirect_uri'] || (params['redirect_uri'] !== authToken.redirectUri)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify({
          error: "invalid_grant",
          error_description: "redirect_uri doesn't match",
        }));
      }
      else if (!params['code_verifier'] || !await codeMatches(params['code_verifier'], authToken.codeChallenge)) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.write(JSON.stringify({
          error: "invalid_request",
          error_description: "code_verifier doesn't match",
        }));
      }
      else {
        res.write(JSON.stringify({
          access_token: authToken.accessTokenKey,
        }, null, 2));
        delete this._tokens[authCode];
        this._persistTokens();
      }

      res.end();
    }
    else if (method === 'setAcl') {
      const gemPath = reqPath.slice(0, -('.gemdrive-acl.tsv'.length));
      await this.setAcl(req, res, gemPath, token);
    }
    else if (method === 'requestPerms') {
      await this.requestPerms(req, res, u, token);
    }
  }

  async setAcl(req, res, gemPath, token) {
    const bodyTsv = await parseBody(req);

    const acl = parseAcl(bodyTsv);
    const valid = validateAcl(acl);

    if (!valid) {
      res.statusCode = 400;
      res.write("Invalid ACL");
      res.end();
      return;
    }

    if (!await this.canOwn(token, gemPath)) {
      res.statusCode = 403;
      res.write(`You don't have owner permissions for ${gemPath}\n`);
      res.end();
      return;
    }

    const aclDir = path.join(this._gemAuthDir, 'acls' + gemPath);
    await fs.promises.mkdir(aclDir, { recursive: true });

    const aclPath = path.join(aclDir, '.gemdrive-acl.tsv');
    await fs.promises.writeFile(aclPath, bodyTsv);

    res.end();
  }

  async requestPerms(req, res, urlObj, token) {
    const bodyJson = await parseBody(req);
    const permRequests = JSON.parse(bodyJson);

    const email = this._getIdent(token);

    for (const request of permRequests) {
      const pathParts = parsePath(request.path);
      const acl = await this._getAcl(pathParts);

      const notifySet = new Set();
      for (const entry of acl) {
        if (entry.perm === 'own') {
          notifySet.add(email);
        }
      }

      const scope = encodeScopeFromPerms(permRequests);
      const reqUrl = `${this._config.host}/.gemdrive/auth/grant?email=${email}&scope=${scope}`;

      for (const notifyEmail of notifySet) {
        await this._emailer.sendMail({
          from: `"pauth authorizer" <${this._config.smtp.sender}>`,
          to: notifyEmail,
          subject: "Access request",
          text: `This is an access request from ${this._config.host}. ${email} is requesting access. Click the following link to handle the request:\n\n ${reqUrl}`,
          //html: "<b>html Hi there</b>"
        });
      }
    }

    res.end();
  }

  async authorize(request) {

    const key = generateKey();

    const verifyUrl = `${this._config.host}?pauth-method=verify&key=${key}`;

    let info = await this._emailer.sendMail({
      from: `"pauth authorizer" <${this._config.smtp.sender}>`,
      to: request.email,
      subject: "Authorization request",
      text: `This is an email verification request from ${this._config.host}. Please click the following link to complete the verification:\n\n ${verifyUrl}`,
      //html: "<b>html Hi there</b>"
    });

    const promise = new Promise((resolve, reject) => {
      const signalDone = () => {
        const newTokenKey = generateKey();
        const newCookieTokenKey = generateKey();

        const timestamp = new Date();

        const token = {
          email: request.email,
          perms: request.perms,
          createdAt: timestamp.toISOString(),
        };

        if (request.maxAge !== undefined) {
          const expireSeconds = timestamp.getSeconds() + request.maxAge;
          timestamp.setSeconds(expireSeconds);
          token.expiresAt = timestamp.toISOString();
        }

        // TODO: don't create token until after verifying ident permissions.
        this._tokens[newTokenKey] = token;
        this._tokens[newCookieTokenKey] = token;
        this._persistTokens();

        resolve({ tokenKey: newTokenKey, cookieTokenKey: newCookieTokenKey });
      };

      this._pendingVerifications[key] = signalDone;

      setTimeout(() => {
        delete this._pendingVerifications[key];
        reject();
      }, 60000);
    });

    const tokenKey = await promise;

    

    return tokenKey;
  }

  async delegateAuthCode(tokenKey, codeChallenge, clientId, redirectUri, request) {

    const accessTokenKey = await this.delegate(tokenKey, request);

    if (!accessTokenKey) {
      return null;
    }

    const authToken = {
      accessTokenKey,
      codeChallenge,
      clientId,
      redirectUri,
    };

    const authCode = generateKey();
    this._tokens[authCode] = authToken;
    this._persistTokens();

    return authCode;
  }

  async delegate(tokenKey, request) {

    const perms = request.perms;

    // TODO: use same format for storing in DB and in code.
    const tokenPerms = {};

    for (let permParams of perms) {

      const path = decodeURIComponent(permParams.path);

      tokenPerms[path] = {};

      if (permParams.perm === 'read') {
        if (!await this.canRead(tokenKey, path)) {
          return null;
        }

        tokenPerms[path].read = true;
      }

      if (permParams.perm === 'write') {
        if (!await this.canWrite(tokenKey, path)) {
          return null;
        }

        tokenPerms[path].write = true;
      }
    }

    const parentToken = this._tokens[tokenKey];

    const newTokenKey = generateKey();

    const timestamp = new Date();

    const token = {
      email: parentToken.email,
      perms: tokenPerms,
      createdAt: timestamp.toISOString(),
    };

    if (parentToken.expiresAt !== undefined) {
      token.expiresAt = parentToken.expiresAt;
    }

    if (request.maxAge !== undefined) {

      const expireSeconds = timestamp.getSeconds() + request.maxAge;
      timestamp.setSeconds(expireSeconds);
      token.expiresAt = timestamp.toISOString();

      if (parentToken.expiresAt) {
        const parentExpireDate = new Date(Date.parse(parentToken.expiresAt));
        if (timestamp > parentExpireDate) {
          return null;
        }
      }
    }

    this._tokens[newTokenKey] = token;
    this._persistTokens();

    return newTokenKey;
  }

  verify(key) {

    if (this._pendingVerifications[key] === undefined) {
      return false;
    }

    this._pendingVerifications[key]();
    delete this._pendingVerifications[key];
    return true;
  }

  async tokenHasPerms(tokenKey, requests) {

    for (const request of requests) {

      const perm = request.perm;
      const path = request.path;

      if (perm === 'read') {
        if (!await this.canRead(tokenKey, path)) {
          return false;
        }
      }
      else if (perm === 'write') {
        if (!await this.canWrite(tokenKey, path)) {
          return false;
        }
      }
      else if (perm === 'own') {
        if (!await this.canOwn(tokenKey, path)) {
          return false;
        }
      }
    }

    return true;
  }

  async getPerms(token) {
    return new Perms(this, token);
  }

  async canRead(token, path) {
    const ident = this._getIdent(token);
    const parts = parsePath(path);

    const acl = await this._getAcl(parts);

    if (aclIdentCanRead(acl, 'public')) {
      return true;
    }
    
    const tokenPerms = this._getTokenPerms(token, parts);
    if (tokenPerms === null) {
      return false;
    }

    const tokenCanRead = tokenPerms.read === true ||
      tokenPerms.write === true ||
      tokenPerms.manage === true ||
      tokenPerms.own === true;

    return tokenCanRead && aclIdentCanRead(acl, ident);
  }

  async canWrite(token, path) {
    const ident = this._getIdent(token);
    const parts = parsePath(path);

    const acl = await this._getAcl(parts);

    if (aclIdentCanWrite(acl, 'public')) {
      return true;
    }

    const tokenPerms = this._getTokenPerms(token, parts);
    if (tokenPerms === null) {
      return false;
    }

    const tokenCanWrite = tokenPerms.write === true ||
      tokenPerms.manage === true ||
      tokenPerms.own === true;

    return aclIdentCanWrite(acl, ident) && tokenCanWrite;
  }

  async canOwn(token, path) {
    const ident = this._getIdent(token);
    const parts = parsePath(path);

    const acl = await this._getAcl(parts);

    const tokenPerms = this._getTokenPerms(token, parts);
    if (tokenPerms === null) {
      return false;
    }

    const tokenCanOwn = tokenPerms.own === true;

    return aclIdentCanOwn(acl, ident) && tokenCanOwn;
  }

  async _getAcl(pathParts) {
    const aclDir = path.join(this._gemAuthDir, 'acls');
    const parts = pathParts.slice();

    for (let i = parts.length; i > -1; i--) {
      const pathStr = encodePath(parts);
      const aclPath = path.join(aclDir, pathStr, '.gemdrive-acl.tsv');
      try {
        const aclText = await fs.promises.readFile(aclPath, 'utf8');
        const acl = parseAcl(aclText);
        return acl;
      }
      catch (e) {
        //console.log(e);
      }

      parts.pop();
    }

    return null;
  }

  _getTokenPerms(tokenKey, pathParts) {
    if (!this._tokens[tokenKey]) {
      return null;
    }

    const token = this._tokens[tokenKey];

    if (token.expiresAt !== undefined) {
      const timeNow = new Date();
      if (timeNow.toISOString() > token.expiresAt) {
        return null;
      }
    }

    const perms = token.perms;

    const tokenPerms = {
      read: false,
      write: false,
      manage: false,
      own: false,
    };

    if (perms['/'] !== undefined) {
      tokenPerms.read = perms['/'].read;
      tokenPerms.write = perms['/'].write;
      tokenPerms.manage = perms['/'].manage;
      tokenPerms.own = perms['/'].own;
    }

    let curPath = '';
    for (const part of pathParts) {
      curPath += '/' + part;
      if (perms[curPath]) {
        if (perms[curPath].read === true) {
          tokenPerms.read = true;
        }
        if (perms[curPath].write === true) {
          tokenPerms.write = true;
        }
        if (perms[curPath].manage === true) {
          tokenPerms.manage = true;
        }
        if (perms[curPath].own === true) {
          tokenPerms.own = true;
        }
      }
    }

    return tokenPerms;
  }

  async _persistTokens() {
    const tokensJson = JSON.stringify(this._tokens, null, 2);
    await fs.promises.writeFile(path.join(this._authDir, 'tokens.json'), tokensJson);
  }

  _getIdent(token) {
    if (this._tokens[token]) {
      return this._tokens[token].email;
    }
    else {
      return 'public';
    }
  }
}

async function persistJson(data, path) {
    const text = JSON.stringify(data, null, 2);
    await fs.promises.writeFile(path, text);
}

class Perms {
  constructor(pauth, token) {
    this._pauth = pauth;
    this._token = token;
  }

  async canRead(path) {
    return await this._pauth.canRead(this._token, path);
  }

  async canWrite(path) {
    return await this._pauth.canWrite(this._token, path);
  }
}

function encodePath(parts) {
  return '/' + parts.join('/');
}

function parsePath(path) {
  if (path.endsWith('/')) {
    path = path.slice(0, path.length - 1);
  }

  if (path === '' || path === '/') {
    return [];
  }

  return path.slice(1).split('/');
}

function generateKey() {
  const possible = "0123456789abcdefghijkmnpqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

  function genCluster() {
    let cluster = "";
    for (let i = 0; i < 32; i++) {
      const randIndex = Math.floor(Math.random() * possible.length);
      cluster += possible[randIndex];
    }
    return cluster;
  }

  let id = "";
  id += genCluster();
  //id += '-';
  //id += genCluster();
  //id += '-';
  //id += genCluster();
  return id;
}

async function parseBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (chunk) => {
      data += chunk;
    });

    req.on('end', async () => {
      resolve(data);
    });

    req.on('error', async (err) => {
      reject(err);
    });
  });
}

function parsePermsFromScope(scope) {

  const allPerms = [];

  const items = scope.split(' ');
  for (const item of items) {
    const perms = {};
    const params = item.split(';');
    for (const param of params) {
      const parts = param.split('=');
      const key = parts[0];
      const value = parts[1];
      perms[key] = value.replace(/\[\]/g, ' ');
    }

    allPerms.push(perms);
  }

  return allPerms;
}

function encodeScopeFromPerms(perms) {
  let scope = '';

  for (const permParams of perms) {

    scope += `type=${permParams.type};perm=${permParams.perm}`;

    if (permParams.path) {
      const path = permParams.path;
      const trimmedPath = path.length > 1 && path.endsWith('/') ? path.slice(0, path.length - 1) : path;
      scope += `;path=${trimmedPath.replace(/ /g, '[]')}`;
    }

    scope += ' ';
  }

  // remove trailing space
  return scope.slice(0, scope.length - 1);
}

async function codeMatches(codeVerifier, codeChallenge) {

  const base64Code = crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

  return base64Code === codeChallenge;
}

function parseAcl(tsvText) {
  const lines = tsvText.split('\n');

  const acl = [];

  for (const row of lines) {
    if (row.length === 0) {
      continue;
    }

    const columns = row.split('\t');

    acl.push({
      idType: columns[0],
      id: columns[1],
      perm: columns[2],
    });
  }

  return acl;
}

// TODO: check for duplicate entries
function validateAcl(acl) {
  for (const entry of acl) {
    if (!['email', 'builtin'].includes(entry.idType)) {
      return false;
    }

    if (!['read', 'write', 'own'].includes(entry.perm)) {
      return false;
    }
  }

  return true;
}

function aclIdentCanRead(acl, ident) {
  return aclIdentHasPerm(acl, ident, ['read', 'write', 'own']);
}
function aclIdentCanWrite(acl, ident) {
  return aclIdentHasPerm(acl, ident, ['write', 'own']);
}
function aclIdentCanOwn(acl, ident) {
  return aclIdentHasPerm(acl, ident, ['own']);
}
function aclIdentHasPerm(acl, ident, permList) {

  if (!acl) {
    return false;
  }

  for (const entry of acl) {
    if (entry.id === ident && permList.includes(entry.perm)) {
      return true;
    }
  }

  return false;
}


module.exports = {
  PauthBuilder,
};
