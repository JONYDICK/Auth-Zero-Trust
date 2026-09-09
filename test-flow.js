const fs = require('fs');
const crypto = require('crypto');

const api = fs.readFileSync('C:/Auth Zero trust/api.php', 'utf8');
const match = api.match(/const\s+SRP_N(?:_LEGACY)?\s*=\s*'([0-9A-F]+)'/i);
if (!match) {
  throw new Error('No se encontró la constante SRP_N en api.php.');
}
const N = BigInt('0x' + match[1]);
const G = 2n;
const K = 3n;
const BASE_URL = process.env.SRP_BASE_URL || 'http://127.0.0.1:8000';
const hex = (buffer) => Buffer.from(buffer).toString('hex');
const bytes = (value) => Buffer.from(value, 'hex');
const sha = (value) => crypto.createHash('sha256').update(value).digest();
const bigIntFromHex = (value) => BigInt('0x' + value);
const evenHex = (value) => {
  const result = value.toString(16);
  return result.length % 2 === 0 ? result : `0${result}`;
};
const mod = (value, modulus) => ((value % modulus) + modulus) % modulus;

function modPow(base, exponent, modulus) {
  let result = 1n;
  base %= modulus;
  while (exponent > 0n) {
    if (exponent & 1n) result = (result * base) % modulus;
    base = (base * base) % modulus;
    exponent >>= 1n;
  }
  return result;
}

async function post(action, payload, cookie = '') {
  const headers = { 'content-type': 'application/json' };
  if (cookie) headers.cookie = cookie;
  const response = await fetch(`${BASE_URL}/api.php?action=${action}`, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    throw new Error(`${action} devolvió una respuesta no JSON HTTP ${response.status}: ${text}`);
  }
  if (!response.ok) {
    throw new Error(`${action} HTTP ${response.status}: ${JSON.stringify(data)}`);
  }
  return { data, cookie: response.headers.get('set-cookie') || cookie };
}

(async () => {
  const username = `test_${Date.now()}`;
  const password = 'CorrectHorseBatteryStaple!';
  const salt = crypto.randomBytes(16);
  const x = bigIntFromHex(hex(sha(Buffer.concat([salt, sha(Buffer.from(`${username}:${password}`))]))));
  const verifier = modPow(G, x, N);

  const registered = await post('register', {
    username,
    salt: salt.toString('hex'),
    verifier: evenHex(verifier),
  });
  const cookie = registered.cookie.split(';')[0];

  const a = bigIntFromHex(crypto.randomBytes(32).toString('hex'));
  const A = modPow(G, a, N);
  const challenge = await post('challenge', { username, A: evenHex(A) }, cookie);
  const B = bigIntFromHex(challenge.data.B);
  const u = bigIntFromHex(hex(sha(Buffer.concat([bytes(evenHex(A)), bytes(challenge.data.B)]))));
  const gx = modPow(G, x, N);
  const base = mod(B - K * gx, N);
  const S = modPow(base, a + u * x, N);
  const M1 = hex(sha(Buffer.concat([bytes(evenHex(A)), bytes(challenge.data.B), bytes(evenHex(S))])));

  const verified = await post('verify', { username, M1 }, cookie);
  console.log(JSON.stringify({ register: registered.data, challenge: challenge.data, verify: verified.data }, null, 2));
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
