import { EFF_LARGE_WORDLIST } from "./wordlist.ts";
import { sodium } from "./sodium.ts";

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  /** Excludes look-alike characters such as 0/O and 1/l/I. */
  avoidAmbiguous: boolean;
}

export const DEFAULT_PASSWORD_OPTIONS: PasswordOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
};

const SETS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?/~",
} as const;
const AMBIGUOUS = new Set("0O1lI|`'\"");

/** Uniform integer in [0, n) without modulo bias. */
function uniform(n: number): number {
  return sodium().randombytes_uniform(n);
}

function pick(chars: string): string {
  return chars[uniform(chars.length)]!;
}

export function generatePassword(options: Partial<PasswordOptions> = {}): string {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  const length = Math.max(4, Math.min(128, Math.floor(opts.length)));
  const filter = (s: string) => (opts.avoidAmbiguous ? [...s].filter((c) => !AMBIGUOUS.has(c)).join("") : s);

  const sets = (Object.keys(SETS) as (keyof typeof SETS)[]).filter((k) => opts[k]).map((k) => filter(SETS[k]));
  if (sets.length === 0) sets.push(filter(SETS.lowercase));

  // At least one character from each selected set; the rest from the combined pool.
  const chars = sets.map(pick);
  const pool = sets.join("");
  while (chars.length < length) chars.push(pick(pool));

  // Fisher-Yates shuffle
  for (let i = chars.length - 1; i > 0; i--) {
    const j = uniform(i + 1);
    [chars[i], chars[j]] = [chars[j]!, chars[i]!];
  }
  return chars.join("");
}

export interface PassphraseOptions {
  /** Number of words (3-20) */
  words: number;
  separator: string;
  /** Capitalize each word. */
  capitalize: boolean;
  /** Append a random digit to one random word. */
  includeNumber: boolean;
}

export const DEFAULT_PASSPHRASE_OPTIONS: PassphraseOptions = { words: 5, separator: "-", capitalize: true, includeNumber: true };

/** Passphrase from the EFF large wordlist, e.g. "Canyon-Oxidize-Pellet7-Blurry-Thaw" (5 words = 64.6 bits). */
export function generatePassphrase(options: Partial<PassphraseOptions> = {}): string {
  const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  const count = Math.max(3, Math.min(20, Math.floor(opts.words)));
  const words = Array.from({ length: count }, () => {
    const w = EFF_LARGE_WORDLIST[uniform(EFF_LARGE_WORDLIST.length)]!;
    return opts.capitalize ? w.charAt(0).toUpperCase() + w.slice(1) : w;
  });
  if (opts.includeNumber) {
    const i = uniform(count);
    words[i] = `${words[i]}${uniform(10)}`;
  }
  return words.join(opts.separator);
}

/** Passphrase entropy in bits, including the optional digit and its position. */
export function passphraseEntropyBits(options: Partial<PassphraseOptions> = {}): number {
  const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  const count = Math.max(3, Math.min(20, Math.floor(opts.words)));
  return count * Math.log2(EFF_LARGE_WORDLIST.length) + (opts.includeNumber ? Math.log2(10 * count) : 0);
}

export interface StrengthResult {
  /** 0 (very weak) to 4 (very strong) */
  score: 0 | 1 | 2 | 3 | 4;
  entropyBits: number;
}

/** Rough entropy estimate that penalizes repeats and sequences. Does not model dictionary attacks. */
export function estimateStrength(password: string): StrengthResult {
  if (!password) return { score: 0, entropyBits: 0 };
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(password)) pool += 33;

  const chars = [...password];
  let effective = 0;
  for (let i = 0; i < chars.length; i++) {
    const prev = chars[i - 1];
    const cur = chars[i]!;
    if (prev === cur) effective += 0.25;
    else if (prev && Math.abs(cur.charCodeAt(0) - prev.charCodeAt(0)) === 1) effective += 0.5;
    else effective += 1;
  }
  const entropyBits = Math.round(effective * Math.log2(Math.max(pool, 2)));
  const score = entropyBits < 28 ? 0 : entropyBits < 40 ? 1 : entropyBits < 60 ? 2 : entropyBits < 80 ? 3 : 4;
  return { score, entropyBits };
}
