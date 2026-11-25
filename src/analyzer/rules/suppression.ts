/**
 * Suppression and Allowlist Utilities for Deterministic Security Scanner.
 * Enforces strict exact-match verification against authoritative vendor documentation
 * and provides entropy calculations for generic credential heuristics.
 */

/**
 * Authoritative provider-documented example credentials.
 * Only canonical dummy values published in official vendor documentation are permitted.
 * Match criteria: Exact complete-value equality ONLY (case-sensitive, trimmed).
 * No prefix, regex, or partial matching is allowed.
 */
export const AUTHORITATIVE_ALLOWLIST = new Set<string>([
  // AWS Official Documentation (docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
  'AKIAIOSFODNN7EXAMPLE',
  // AWS Official Documentation (docs.aws.amazon.com/STS/latest/APIReference/API_Credentials.html)
  'ASIAIOSFODNN7EXAMPLE',
  // AWS Official Documentation (docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html)
  'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  // Slack Official API Documentation (api.slack.com/messaging/webhooks)
  'https://hooks.slack.com/' + 'services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX'
]);

/**
 * Validates whether a candidate string is an exact match for an authoritative documentation example.
 */
export function isAllowlistedExample(value: string): boolean {
  if (!value) return false;
  return AUTHORITATIVE_ALLOWLIST.has(value.trim());
}

/**
 * Curated exact-match placeholder tokens for generic assignment heuristics.
 * Applied only to candidate values matching generic variable assignments, never provider signatures.
 */
export const KNOWN_PLACEHOLDERS = new Set<string>([
  'YOUR_API_KEY_HERE',
  'REPLACE_WITH_YOUR_KEY',
  'ENTER_PASSWORD_HERE',
  'CHANGE_ME',
  'INSERT_SECRET_HERE',
  'TODO_ADD_SECRET',
  'YOUR_SECRET_KEY',
  'REPLACE_ME'
]);

export function isKnownPlaceholder(value: string): boolean {
  if (!value) return false;
  return KNOWN_PLACEHOLDERS.has(value.trim().toUpperCase());
}

/**
 * Computes the Shannon entropy of a string in bits per character.
 * H(X) = -sum(p(x) * log2(p(x)))
 */
export function calculateShannonEntropy(str: string): number {
  if (!str || str.length === 0) return 0;

  const frequencies = new Map<string, number>();
  for (const char of str) {
    frequencies.set(char, (frequencies.get(char) || 0) + 1);
  }

  let entropy = 0;
  const len = str.length;
  for (const count of frequencies.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }

  return entropy;
}

/**
 * Checks if a string contains characters from at least minClasses distinct character classes:
 * 1. Lowercase ASCII [a-z]
 * 2. Uppercase ASCII [A-Z]
 * 3. Digits [0-9]
 * 4. Symbols / Special Characters
 */
export function hasCharacterDiversity(str: string, minClasses = 3): boolean {
  if (!str) return false;

  let classes = 0;
  if (/[a-z]/.test(str)) classes++;
  if (/[A-Z]/.test(str)) classes++;
  if (/[0-9]/.test(str)) classes++;
  if (/[^a-zA-Z0-9]/.test(str)) classes++;

  return classes >= minClasses;
}

