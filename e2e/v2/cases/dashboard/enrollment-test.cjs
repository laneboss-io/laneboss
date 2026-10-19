// Linux-only browser-adapter fixture. Real attestation verification is covered
// by TestBrowserEnrollment; this inert DOM makes no hardware-presence claim.
'use strict';
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

module.exports = async function enrollmentChecks() {
  for (const mode of ['valid', 'foreign', 'refused', 'simulated']) {
    let click;
    let created = 0;
    let completed = 0;
    const button = {disabled: false, addEventListener: (name, callback) => {
      assert.equal(name, 'click'); click = callback;
    }};
    const status = {textContent: ''};
    const challenge = crypto.randomBytes(32);
    const user = crypto.randomBytes(16);
    const attestation = crypto.randomBytes(128);
    const client = Buffer.from(JSON.stringify({type: 'webauthn.create', origin: 'https://console.example.test',
      challenge: challenge.toString('base64url')}));
    const context = {
      document: {getElementById: (id) => id === 'enroll-key' ? button : status},
      window: {isSecureContext: true, PublicKeyCredential: class {}, location: {origin: 'https://console.example.test'}},
      atob: (value) => Buffer.from(value, 'base64').toString('binary'),
      btoa: (value) => Buffer.from(value, 'binary').toString('base64'),
      navigator: {credentials: {create: async ({publicKey}) => {
        created++;
        assert.deepEqual(Buffer.from(publicKey.challenge), challenge, 'browser lost the service registration nonce');
        assert.deepEqual(Buffer.from(publicKey.user.id), user, 'browser lost the protected principal handle');
        assert.equal(publicKey.rp.id, 'console.example.test', 'browser replaced the installed RP ID');
        assert.equal(publicKey.authenticatorSelection.userVerification, 'required', 'browser weakened enrollment user verification');
        assert.equal(publicKey.authenticatorSelection.authenticatorAttachment, 'cross-platform');
        assert.equal(publicKey.attestation, 'direct', 'browser omitted direct attestation');
        return {type: 'public-key', response: {clientDataJSON: client, attestationObject: attestation}};
      }}},
      fetch: async (url, options) => {
        assert.equal(options.method, 'POST');
        assert.equal(options.credentials, 'same-origin');
        assert.equal(options.headers['Content-Type'], 'application/json');
        const body = JSON.parse(options.body);
        if (url.endsWith('/begin')) {
          assert.deepEqual(body, {});
          return {ok: true, json: async () => ({challenge: challenge.toString('base64'), user_id: user.toString('base64'),
            origin: mode === 'foreign' ? 'https://foreign.example' : 'https://console.example.test', rp_id: 'console.example.test'})};
        }
        assert.equal(url, '/api/v2/enrollment/complete');
        completed++;
        assert.deepEqual(Object.keys(body).sort(), ['attestation_object', 'client_data_json'], 'browser added enrollment authority or software marker');
        assert.deepEqual(Buffer.from(body.client_data_json, 'base64'), client, 'browser changed client registration bytes');
        assert.deepEqual(Buffer.from(body.attestation_object, 'base64'), attestation, 'browser changed attestation bytes');
        const digest = crypto.createHash('sha256').update(options.body).digest('hex');
        return {ok: mode !== 'refused', json: async () => mode === 'refused' ? {error: {code: 'forbidden', message: 'Security-key attestation refused by identity.'}} :
          {OperationID: digest, CommittedSeq: completed, SimulatedPresence: mode === 'simulated'}};
      },
    };
    const source = fs.readFileSync(path.resolve(__dirname, '../../../../web/v2/enrollment.js'), 'utf8');
    vm.runInNewContext(source, context, {filename: 'enrollment.js'});
    assert.equal(typeof click, 'function', 'enrollment button did not bind its ceremony');
    await click();
    assert.equal(button.disabled, false);
    if (mode === 'foreign') {
      assert.equal(created, 0, 'browser accepted a foreign installed origin');
      assert.equal(completed, 0);
      assert.match(status.textContent, /does not match/);
    } else if (mode === 'refused') {
      assert.equal(completed, 1);
      assert.match(status.textContent, /refused/, 'browser reported refused registration as enrolled');
      assert.equal(status.textContent, 'Security-key attestation refused by identity.', 'browser hid the identity attestation refusal');
    } else if (mode === 'simulated') {
      assert.equal(completed, 1);
      assert.match(status.textContent, /did not return a committed real-device/, 'browser admitted a simulated enrollment receipt');
    } else {
      assert.match(status.textContent, /^Security key enrolled/, 'browser lost successful enrollment receipt: ' + status.textContent);
      assert.equal(created, 1, 'browser did not invoke WebAuthn registration');
      assert.equal(completed, 1);
    }
  }
};
