/**
 * Password rules shown at registration. The API is the authority; this is only a hint.
 */
export const MIN_PASSWORD_LENGTH = 12;

export type PasswordStrength = "tooShort" | "weak" | "fair" | "strong";

export function passwordStrength(password: string): PasswordStrength {
  if (password.length < MIN_PASSWORD_LENGTH) return "tooShort";
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  const distinct = new Set(password).size;
  let score = classes;
  if (password.length >= 16) score += 1;
  if (password.length >= 20) score += 1;
  if (distinct < 6) score -= 2;
  if (score >= 4) return "strong";
  if (score >= 2) return "fair";
  return "weak";
}
