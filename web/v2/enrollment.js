'use strict';
(() => {
  const button = document.getElementById('enroll-key');
  const status = document.getElementById('enrollment-status');
  const decode = (value) => Uint8Array.from(atob(value), (c) => c.charCodeAt(0));
  const encode = (value) => {
    let text = '';
    for (const byte of new Uint8Array(value)) text += String.fromCharCode(byte);
    return btoa(text);
  };
  async function post(path, body) {
    const response = await fetch(path, {
      method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body),
    });
    const result = await response.json();
    if (!response.ok || result.error) throw new Error(result.error && typeof result.error.message === 'string' && result.error.message
      ? result.error.message : 'The protected enrollment ceremony refused this request. Check the administrator ceremony and retry.');
    return result;
  }
  button.addEventListener('click', async () => {
    button.disabled = true;
    try {
      if (!window.isSecureContext || !navigator.credentials || !window.PublicKeyCredential) {
        throw new Error('Use a browser with WebAuthn on the installed HTTPS origin.');
      }
      const options = await post('/api/v2/enrollment/begin', {});
      if (options.origin !== window.location.origin) throw new Error('The installed enrollment origin does not match this page.');
      status.textContent = 'Connect your security key and verify your presence when the browser asks.';
      const credential = await navigator.credentials.create({publicKey: {
        challenge: decode(options.challenge),
        rp: {id: options.rp_id, name: 'Laneboss'},
        user: {id: decode(options.user_id), name: 'Owner', displayName: 'Owner'},
        pubKeyCredParams: [{type: 'public-key', alg: -7}, {type: 'public-key', alg: -8}, {type: 'public-key', alg: -257}],
        authenticatorSelection: {authenticatorAttachment: 'cross-platform', userVerification: 'required'},
        attestation: 'direct', timeout: 120000,
      }});
      if (!credential || credential.type !== 'public-key' || !credential.response) throw new Error('Security-key registration did not complete.');
      const receipt = await post('/api/v2/enrollment/complete', {
        client_data_json: encode(credential.response.clientDataJSON),
        attestation_object: encode(credential.response.attestationObject),
      });
      if (receipt.SimulatedPresence || !receipt.CommittedSeq) throw new Error('The service did not return a committed real-device enrollment receipt.');
      status.textContent = 'Security key enrolled. You can close this page.';
    } catch (error) {
      status.textContent = error.name === 'NotAllowedError' ? 'Registration was cancelled or timed out. You can try again.' : error.message;
    } finally {
      button.disabled = false;
    }
  });
})();
