// Type definitions for @shielderx/runtime
// Project: https://shielderx.com

/**
 * Resolves an encrypted secret placeholder to its decrypted value.
 * 
 * @param placeholder - The secret placeholder (e.g., "<SECRET_289F50EE>")
 * @returns The decrypted secret value as a string
 */
export function resolveSecret(placeholder: string): string;