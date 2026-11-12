// Shared account-safety policy (server enforces, client mirrors for warnings).
export const RESERVED_USERNAMES = new Set([
  'admin', 'administrator', 'root', 'system', 'support', 'help', 'helpdesk', 'security', 'official', 'qchat', 'qchat_support',
  'qchatsupport', 'qchat.support', 'qchat_official', 'staff', 'team', 'moderator', 'mod', 'abuse', 'postmaster', 'webmaster',
  'noreply', 'no_reply', 'verify', 'verification', 'billing', 'payments', 'account', 'accounts', 'service', 'customer_service',
  'trust', 'safety', 'legal', 'privacy', 'ceo', 'owner',
]);
// names that try to look official
const IMPERSONATION = /(q\s*chat|official|support\s*team|customer\s*(care|service)|security\s*team|verified|admin(istrator)?|moderator|staff|help\s*desk|[✓✔☑])/i;
// bidi overrides, zero-width & other invisible/control characters used for spoofing
export const INVISIBLE = /[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁠-⁯﻿᠎]/g;

export function isReservedUsername(u) {
  const x = String(u).toLowerCase();
  return RESERVED_USERNAMES.has(x) || /^(qchat|admin|support|security|official)[._]?/.test(x);
}
export function cleanText(s, max) { return String(s ?? '').replace(INVISIBLE, '').replace(/\s+/g, ' ').trim().slice(0, max); }
export function looksLikeImpersonation(displayName) { return IMPERSONATION.test(String(displayName || '')); }
