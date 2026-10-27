// CLI: tsx checker/run-vectors.ts vectors/vectors.json [--only <id>] [--json <out>]
// Decodes each vector's inputs (vectors/README.md), runs verify(), compares with `expect`, prints one
// line per vector and the totals, optionally writes a JSON result file, and exits non-zero on failure.
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { execSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { b64uDecode, isPlainObject } from './encoding.ts';
import { verify, type Output, type VerifyInputs } from './verify.ts';

const CHECKER = { name: 'x402-acceptance-record/conformance/checker', language: 'typescript', version: '0.1.0' };

/** The git commit the checker ran at, and whether the checker's own files had uncommitted changes. */
function gitPin(): { commit: string; dirty: boolean } {
  const here = dirname(fileURLToPath(import.meta.url));
  const git = (args: string) => execSync(`git ${args}`, { cwd: here, stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
  try {
    return { commit: git('rev-parse HEAD'), dirty: git('status --porcelain -- .') !== '' };
  } catch {
    return { commit: 'unknown', dirty: true };
  }
}
const ASSERTED_MEMBERS = ['disposition', 'reason', 'policy_refusal'] as const;

interface Vector {
  id: string;
  case?: string;
  variant?: string;
  form?: string;
  title?: string;
  note?: string;
  inputs: unknown;
  expect: unknown;
}

interface VectorResult {
  id: string;
  case?: string;
  variant?: string;
  form?: string;
  outcome: 'pass' | 'fail';
  expected: unknown;
  actual?: Output;
  differences?: string[];
  error?: string;
}

function usage(message?: string): never {
  if (message) console.error(`error: ${message}`);
  console.error('usage: tsx checker/run-vectors.ts vectors/vectors.json [--only <id>] [--json <out>]');
  process.exit(2);
}

function parseArgs(argv: string[]): { file: string; only: string[]; json: string | null } {
  let file: string | null = null;
  const only: string[] = [];
  let json: string | null = null;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--only') {
      const v = argv[++i];
      if (v === undefined) usage('--only needs an id');
      only.push(...v.split(',').map((s) => s.trim()).filter(Boolean));
    } else if (a === '--json') {
      const v = argv[++i];
      if (v === undefined) usage('--json needs a path');
      json = v;
    } else if (a === '-h' || a === '--help') {
      usage();
    } else if (a.startsWith('--')) {
      usage(`unknown option ${a}`);
    } else if (file === null) {
      file = a;
    } else {
      usage('one vector file only');
    }
  }
  if (file === null) usage('vector file missing');
  return { file, only, json };
}

/** Decodes a vector's `inputs` as vectors/README.md defines them. Throws on a malformed vector. */
export function decodeInputs(raw: unknown): VerifyInputs {
  if (!isPlainObject(raw)) throw new Error('inputs is not an object');
  const bytes = (v: unknown, name: string): Uint8Array => {
    if (typeof v !== 'string') throw new Error(`${name} is not a base64url string`);
    const b = b64uDecode(v);
    if (!b) throw new Error(`${name} is not canonical unpadded base64url`);
    return b;
  };
  if (raw.record !== null && typeof raw.record !== 'string') throw new Error('record must be a base64url string or null');
  if (raw.subject !== null && raw.subject !== undefined && typeof raw.subject !== 'string') throw new Error('subject must be a base64url string or null');
  const termsRaw = raw.terms === undefined ? [] : raw.terms;
  if (!Array.isArray(termsRaw)) throw new Error('terms must be an array');
  if (raw.contractAccounts !== undefined && typeof raw.contractAccounts !== 'boolean') throw new Error('contractAccounts must be a boolean');
  if (raw.chain !== undefined && !Array.isArray(raw.chain)) throw new Error('chain must be an array');
  if (raw.trust !== undefined && !isPlainObject(raw.trust)) throw new Error('trust must be an object');
  return {
    record: raw.record === null ? null : bytes(raw.record, 'record'),
    subject: raw.subject === null || raw.subject === undefined ? null : bytes(raw.subject, 'subject'),
    terms: termsRaw.map((t, i) => bytes(t, `terms[${i}]`)),
    ...(raw.outcome === undefined ? {} : { outcome: bytes(raw.outcome, 'outcome') }),
    trust: (raw.trust ?? {}) as VerifyInputs['trust'],
    chain: (raw.chain ?? []) as VerifyInputs['chain'],
    contractAccounts: raw.contractAccounts === undefined ? true : raw.contractAccounts,
  };
}

/** The differences between `expect` and the checker's output; empty when the vector passes. */
export function compareOutput(expect: unknown, actual: Output): string[] {
  const diffs: string[] = [];
  if (!isPlainObject(expect)) return ['expect is not an object'];
  if (expect.result !== actual.result) diffs.push(`result: expected ${JSON.stringify(expect.result)}, got ${JSON.stringify(actual.result)}`);
  const expectedConditions = Array.isArray(expect.conditions) ? [...new Set(expect.conditions.map(String))].sort() : null;
  const actualConditions = [...new Set(actual.conditions)].sort();
  if (expectedConditions === null) diffs.push('expect.conditions is not an array');
  else if (JSON.stringify(expectedConditions) !== JSON.stringify(actualConditions)) {
    diffs.push(`conditions: expected {${expectedConditions.join(', ')}}, got {${actualConditions.join(', ')}}`);
  }
  for (const key of ASSERTED_MEMBERS) {
    const expected = Object.prototype.hasOwnProperty.call(expect, key);
    const present = Object.prototype.hasOwnProperty.call(actual, key) && actual[key] !== undefined;
    if (expected && (!present || actual[key] !== expect[key])) {
      diffs.push(`${key}: expected ${JSON.stringify(expect[key])}, got ${present ? JSON.stringify(actual[key]) : 'absent'}`);
    } else if (!expected && present) {
      diffs.push(`${key}: expected absent, got ${JSON.stringify(actual[key])}`);
    }
  }
  return diffs;
}

function selected(vector: Vector, only: string[]): boolean {
  if (only.length === 0) return true;
  return only.some((o) => vector.id === o || vector.id.startsWith(`${o}-`));
}

function main(): void {
  const { file, only, json } = parseArgs(process.argv.slice(2));

  let text: Buffer;
  try {
    text = readFileSync(file);
  } catch (e) {
    usage(`cannot read ${file}: ${(e as Error).message}`);
  }
  const sha256 = createHash('sha256').update(text).digest('hex');
  let doc: unknown;
  try {
    doc = JSON.parse(text.toString('utf8'));
  } catch (e) {
    usage(`${file} is not JSON: ${(e as Error).message}`);
  }
  if (!isPlainObject(doc) || !Array.isArray(doc.vectors)) usage(`${file} has no "vectors" array`);
  const vectors = (doc.vectors as unknown[]).filter((v): v is Vector => isPlainObject(v) && typeof v.id === 'string');
  if (vectors.length !== doc.vectors.length) console.error(`warning: ${doc.vectors.length - vectors.length} entries without a string id were skipped`);

  const results: VectorResult[] = [];
  for (const vector of vectors) {
    if (!selected(vector, only)) continue;
    const base = { id: vector.id, case: vector.case, variant: vector.variant, form: vector.form, expected: vector.expect };
    let result: VectorResult;
    try {
      const actual = verify(decodeInputs(vector.inputs));
      const differences = compareOutput(vector.expect, actual);
      result = differences.length === 0 ? { ...base, outcome: 'pass', actual } : { ...base, outcome: 'fail', actual, differences };
    } catch (e) {
      result = { ...base, outcome: 'fail', error: e instanceof Error ? `${e.constructor.name}: ${e.message}` : String(e) };
    }
    results.push(result);
    if (result.outcome === 'pass') {
      console.log(`PASS ${result.id}`);
    } else {
      console.log(`FAIL ${result.id}`);
      console.log(`  expected: ${JSON.stringify(result.expected)}`);
      if (result.actual) console.log(`  actual:   ${JSON.stringify(result.actual)}`);
      for (const d of result.differences ?? []) console.log(`  - ${d}`);
      if (result.error) console.log(`  error: ${result.error}`);
    }
  }

  const passed = results.filter((r) => r.outcome === 'pass').length;
  const failed = results.length - passed;
  console.log(`${results.length} vectors: ${passed} passed, ${failed} failed (${file} sha256 ${sha256})`);
  if (results.length === 0) console.error('warning: no vector selected');

  if (json !== null) {
    const report = {
      checker: { ...CHECKER, ...gitPin() },
      vectorFile: { path: file, sha256 },
      profile: doc.profile,
      specification: doc.specification,
      ranAt: new Date().toISOString(),
      totals: { vectors: results.length, passed, failed },
      results,
    };
    writeFileSync(json, JSON.stringify(report, null, 2) + '\n');
    console.log(`wrote ${json}`);
  }

  process.exit(failed > 0 || results.length === 0 ? 1 : 0);
}

// Run only as the CLI entry point, so the functions above can be imported by tests.
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
