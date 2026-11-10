// Donations. The address is compiled into the app (not fetched from the server), so a compromised or
// malicious server can't swap it for an attacker's address. Its bech32 checksum is verified before it is shown.
export const DONATE_BTC = 'bc1qrdscfgplay3vstk3zhefn7fyhcxhxn2ssp4nzv';

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
function polymod(values) {
  const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) { const b = chk >>> 25; chk = ((chk & 0x1ffffff) << 5) ^ v; for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= G[i]; }
  return chk >>> 0;
}
/** True for a well-formed mainnet SegWit address (bech32 for v0, bech32m for v1+ / Taproot). */
export function validBtcAddress(addr) {
  if (typeof addr !== 'string' || addr.length < 14 || addr.length > 74 || addr !== addr.toLowerCase()) return false;
  const p = addr.lastIndexOf('1'); if (p < 1 || addr.slice(0, p) !== 'bc') return false;
  const data = [...addr.slice(p + 1)].map((c) => CHARSET.indexOf(c)); if (data.length < 7 || data.includes(-1)) return false;
  const hrp = addr.slice(0, p);
  const exp = [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];
  const c = polymod([...exp, ...data]);
  return data[0] === 0 ? c === 1 : c === 0x2bc830a3;
}
/** "bc1q rdsc fgpl …" — groups of 4 so people can check it character by character against their wallet. */
export const groupAddress = (a) => a.match(/.{1,4}/g).join(' ');
