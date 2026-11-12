import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, analyzeMessage, analyzeFile, containsRecoveryKey, extractUrls } from '../src/shared/linksafety.js';

const lvl = (u, ctx) => analyzeUrl(u, ctx).level;
test('phishing links are flagged as dangerous', () => {
  for (const u of ['https://paypa1.com/login', 'https://paypal-secure-login.top/verify', 'https://www.paypal.com@evil.example/', 'http://192.168.4.20/bank',
    'https://xn--pypal-4ve.com/', 'https://apple.id-verify-account.com/unlock', 'https://g00gle.com/', 'https://faceb00k-security.xyz/', 'https://mpesa-refund.click/claim',
    'https://download.example.com/invoice.pdf.exe', 'https://update.zip/', 'javascript:alert(1)'])
    assert.equal(lvl(u), 'danger', u);
});
test('official sites are not flagged as phishing', () => {
  for (const u of ['https://www.paypal.com/signin', 'https://accounts.google.com/', 'https://appleid.apple.com/', 'https://www.safaricom.co.ke/mpesa', 'https://github.com/Rokit12/Q-chat-', 'https://en.wikipedia.org/wiki/Post-quantum_cryptography'])
    assert.notEqual(lvl(u), 'danger', u);
  assert.equal(lvl('https://en.wikipedia.org/wiki/Lagos'), 'ok');
});
test('unknown-but-suspicious links get a caution', () => {
  assert.equal(lvl('https://bit.ly/3abcd'), 'caution');
  assert.equal(lvl('http://example.com/'), 'caution');
  assert.equal(lvl('https://example.com/', { stranger: true }), 'caution', 'links from strangers are always flagged');
});
test('social engineering & recovery-key leaks', () => {
  assert.ok(analyzeMessage('Hi, this is QChat Support. Please send me your recovery key to verify your account').asksForSecrets);
  assert.ok(analyzeMessage('QChat security team here: your account will be suspended').claimsOfficial);
  assert.ok(analyzeMessage("what's your passcode?").asksForSecrets);
  assert.ok(!analyzeMessage('Want to grab lunch tomorrow?').risky);
  assert.ok(containsRecoveryKey('here: QC1-' + 'A'.repeat(130)));
  assert.ok(!containsRecoveryKey('QC1 is a nice model'));
});
test('dangerous attachments', () => {
  assert.equal(analyzeFile('setup.exe').level, 'danger');
  assert.equal(analyzeFile('invoice.pdf.exe').level, 'danger');
  assert.equal(analyzeFile('photos.apk').level, 'danger');
  assert.equal(analyzeFile('report.pdf').level, 'ok');
  assert.equal(analyzeFile('site.html').level, 'caution');
});
test('url extraction', () => { assert.deepEqual(extractUrls('see https://a.com/x, and www.b.org.'), ['https://a.com/x', 'www.b.org']); });

test('donation address: built in and checksum-verified (a swapped or mistyped address is refused)', async () => {
  const { DONATE_BTC, validBtcAddress } = await import('../src/client/donate.js');
  assert.ok(validBtcAddress(DONATE_BTC));
  assert.ok(!validBtcAddress(DONATE_BTC.slice(0, -1) + (DONATE_BTC.endsWith('v') ? 'w' : 'v'))); // one character changed
  assert.ok(!validBtcAddress(DONATE_BTC.toUpperCase().replace('BC1', 'bc1')));
  assert.ok(!validBtcAddress('tb1qrdscfgplay3vstk3zhefn7fyhcxhxn2ssp4nzv')); // testnet
  assert.ok(validBtcAddress('bc1p5d7rjq7g6rdk2yhzks9smlaqtedr4dekq08ge8ztwac72sfr9rusxg3297')); // Taproot (bech32m)
});
