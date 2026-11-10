#!/usr/bin/env node
// Admin account management from the server shell (needs the same env as the server: DATA_DIR or ADMIN_DATABASE_URL, ADMIN_SECRET_KEY).
//   node server/admin-cli.js create <username> [--role owner|admin|viewer]     (asks for a password)
//   node server/admin-cli.js list
//   node server/admin-cli.js reset-2fa <username>
//   node server/admin-cli.js unlock <username>
//   node server/admin-cli.js disable|enable <username>
import './env.js';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath } from 'node:url';
import qrcode from 'qrcode-generator';
import { openAdminStore } from './admin-store.js';
import { createAdmin } from './admin.js';
import { newTotpSecret, otpauthUrl, secretBox, hashPassword, passwordProblem } from './admin-auth.js';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const [cmd, name, ...rest] = process.argv.slice(2);
const role = rest[rest.indexOf('--role') + 1] && rest.includes('--role') ? rest[rest.indexOf('--role') + 1] : 'owner';
const adminStore = await openAdminStore({ adminDatabaseUrl: process.env.ADMIN_DATABASE_URL, dataDir: process.env.DATA_DIR || path.join(ROOT, 'data') });

function ask(q, hidden) {
  if (process.env.ADMIN_PASSWORD && hidden) return Promise.resolve(process.env.ADMIN_PASSWORD);
  return new Promise((res) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) rl._writeToOutput = (s) => rl.output.write(s.includes(q) ? s : '*');
    rl.question(q, (a) => { rl.close(); process.stdout.write('\n'); res(a); });
  });
}
function showTotp(username, secret) {
  const url = otpauthUrl('QChat Admin', username, secret);
  const qr = qrcode(0, 'M'); qr.addData(url); qr.make();
  console.log('\nScan this with Google Authenticator, Authy, 1Password, Microsoft Authenticator…\n');
  console.log(qr.createASCII(1, 2));
  console.log(`Or enter the secret manually: ${secret.match(/.{1,4}/g).join(' ')}\n`);
  console.log('Store it now — it will not be shown again.');
}
const box = async () => secretBox(process.env.ADMIN_SECRET_KEY || (await adminStore.getMeta('secret_key')) || '');
try {
  if (cmd === 'create') {
    const pw = await ask(`Password for ${name} (12+ chars): `, true);
    const { addAdmin } = await createAdmin({ adminStore });
    const r = await addAdmin(name, pw, role);
    console.log(`\n✅ Admin "${r.username}" created with role ${r.role}.`); showTotp(r.username, r.totpSecret);
  } else if (cmd === 'list') {
    for (const a of await adminStore.listAdmins()) console.log(`${a.username.padEnd(20)} ${a.role.padEnd(7)} ${Number(a.disabled) ? 'DISABLED' : 'active  '} last login: ${a.last_login ? new Date(a.last_login).toISOString() : 'never'}`);
  } else if (cmd === 'reset-2fa') {
    await createAdmin({ adminStore }); // ensures the secret key exists
    const a = await adminStore.getAdmin(name); if (!a) throw new Error('No such admin');
    const secret = newTotpSecret(); await adminStore.updateAdmin(a.id, { totp_enc: (await box()).seal(secret, 'totp|' + a.username), totp_last: 0 }); await adminStore.deleteSessionsFor(a.id);
    await adminStore.audit('cli', 'reset_2fa', a.username); showTotp(a.username, secret);
  } else if (cmd === 'set-password') {
    const a = await adminStore.getAdmin(name); if (!a) throw new Error('No such admin');
    const pw = await ask('New password: ', true); const prob = passwordProblem(pw); if (prob) throw new Error(prob);
    await adminStore.updateAdmin(a.id, { pw_hash: await hashPassword(pw) }); await adminStore.deleteSessionsFor(a.id); await adminStore.audit('cli', 'set_password', a.username); console.log('✅ Password changed; existing sessions signed out.');
  } else if (['unlock', 'disable', 'enable'].includes(cmd)) {
    const a = await adminStore.getAdmin(name); if (!a) throw new Error('No such admin');
    await adminStore.updateAdmin(a.id, cmd === 'unlock' ? { failed: 0, locked_until: 0 } : { disabled: cmd === 'disable' ? 1 : 0 });
    if (cmd === 'disable') await adminStore.deleteSessionsFor(a.id);
    await adminStore.audit('cli', cmd, a.username); console.log(`✅ ${cmd}d ${a.username}`);
  } else {
    console.log('Usage: node server/admin-cli.js create <username> [--role owner|admin|viewer] | list | reset-2fa <u> | set-password <u> | unlock <u> | disable <u> | enable <u>');
  }
} catch (e) { console.error('❌ ' + e.message); process.exitCode = 1; }
await adminStore.close(); process.exit();
