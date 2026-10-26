// A strict I-JSON reader (RFC 7493, AR-6). It works on bytes, so it can reject text that is not
// UTF-8, and it keeps the lexical text of every number, so `1791500600` can be told apart from
// `1791500600.0`, `1.7915006e9` and `"1791500600"`. Duplicate member names, lone surrogate escapes,
// control characters, a BOM and trailing content are all errors. JSON.parse can do none of this.
import { utf8Decode } from './encoding.ts';

export type JsonNode =
  | { kind: 'object'; members: Map<string, JsonNode> }
  | { kind: 'array'; items: JsonNode[] }
  | { kind: 'string'; value: string }
  | { kind: 'number'; lexeme: string; value: number }
  | { kind: 'boolean'; value: boolean }
  | { kind: 'null' };

const MAX_DEPTH = 64;

/** Parses one JSON text. Returns null for anything that is not a well-formed I-JSON text. */
export function parseStrictJson(bytes: Uint8Array): JsonNode | null {
  const text = utf8Decode(bytes); // AR-6: valid UTF-8
  if (text === null) return null;
  const p = new Parser(text);
  try {
    p.skipWs();
    const value = p.value(0);
    p.skipWs();
    if (p.i !== text.length) return null; // trailing content
    return value;
  } catch {
    return null;
  }
}

/** The member of an object node, or undefined. */
export function member(node: JsonNode | undefined, name: string): JsonNode | undefined {
  return node && node.kind === 'object' ? node.members.get(name) : undefined;
}

/** True when the object has exactly the named members. */
export function hasExactlyMembers(node: JsonNode, names: readonly string[]): boolean {
  if (node.kind !== 'object') return false;
  return node.members.size === names.length && names.every((n) => node.members.has(n));
}

/** Converts the tree to plain JavaScript values, for RFC 8785 canonicalization. */
export function toPlain(node: JsonNode): unknown {
  switch (node.kind) {
    case 'object': {
      const o: Record<string, unknown> = {};
      for (const [k, v] of node.members) {
        // defineProperty keeps a member literally named "__proto__" an own property.
        Object.defineProperty(o, k, { value: toPlain(v), enumerable: true, writable: true, configurable: true });
      }
      return o;
    }
    case 'array':
      return node.items.map(toPlain);
    case 'string':
    case 'number':
    case 'boolean':
      return node.value;
    case 'null':
      return null;
  }
}

class JsonSyntaxError extends Error {}

const NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;

class Parser {
  i = 0;
  constructor(private readonly s: string) {}

  private fail(what: string): never {
    throw new JsonSyntaxError(`${what} at ${this.i}`);
  }

  skipWs(): void {
    while (this.i < this.s.length) {
      const c = this.s.charCodeAt(this.i);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) this.i++;
      else break;
    }
  }

  value(depth: number): JsonNode {
    if (depth > MAX_DEPTH) this.fail('nesting too deep');
    const c = this.s[this.i];
    switch (c) {
      case '{':
        return this.object(depth);
      case '[':
        return this.array(depth);
      case '"':
        return { kind: 'string', value: this.string() };
      case 't':
        this.literal('true');
        return { kind: 'boolean', value: true };
      case 'f':
        this.literal('false');
        return { kind: 'boolean', value: false };
      case 'n':
        this.literal('null');
        return { kind: 'null' };
      default:
        if (c === '-' || (c !== undefined && c >= '0' && c <= '9')) return this.number();
        return this.fail('unexpected character');
    }
  }

  private literal(word: string): void {
    if (this.s.startsWith(word, this.i)) this.i += word.length;
    else this.fail('bad literal');
  }

  private number(): JsonNode {
    NUMBER.lastIndex = this.i;
    const m = NUMBER.exec(this.s);
    if (!m || m.index !== this.i) this.fail('bad number');
    const lexeme = m[0];
    this.i += lexeme.length;
    return { kind: 'number', lexeme, value: Number(lexeme) };
  }

  private object(depth: number): JsonNode {
    this.i++; // {
    const members = new Map<string, JsonNode>();
    this.skipWs();
    if (this.s[this.i] === '}') {
      this.i++;
      return { kind: 'object', members };
    }
    for (;;) {
      if (this.s[this.i] !== '"') this.fail('expected member name');
      const name = this.string();
      this.skipWs();
      if (this.s[this.i] !== ':') this.fail('expected colon');
      this.i++;
      this.skipWs();
      const v = this.value(depth + 1);
      if (members.has(name)) this.fail('duplicate member name'); // AR-6: no duplicate member names
      members.set(name, v);
      this.skipWs();
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        this.skipWs();
        continue;
      }
      if (c === '}') {
        this.i++;
        return { kind: 'object', members };
      }
      this.fail('expected comma or end of object');
    }
  }

  private array(depth: number): JsonNode {
    this.i++; // [
    const items: JsonNode[] = [];
    this.skipWs();
    if (this.s[this.i] === ']') {
      this.i++;
      return { kind: 'array', items };
    }
    for (;;) {
      items.push(this.value(depth + 1));
      this.skipWs();
      const c = this.s[this.i];
      if (c === ',') {
        this.i++;
        this.skipWs();
        continue;
      }
      if (c === ']') {
        this.i++;
        return { kind: 'array', items };
      }
      this.fail('expected comma or end of array');
    }
  }

  private hex4(): number {
    const h = this.s.slice(this.i, this.i + 4);
    if (!/^[0-9a-fA-F]{4}$/.test(h)) this.fail('bad unicode escape');
    this.i += 4;
    return Number.parseInt(h, 16);
  }

  private string(): string {
    this.i++; // opening quote
    let out = '';
    for (;;) {
      if (this.i >= this.s.length) this.fail('unterminated string');
      const c = this.s.charCodeAt(this.i);
      if (c === 0x22) {
        this.i++;
        return out;
      }
      if (c < 0x20) this.fail('control character in string');
      if (c !== 0x5c) {
        out += this.s[this.i++];
        continue;
      }
      this.i++; // backslash
      const e = this.s[this.i++];
      switch (e) {
        case '"': out += '"'; break;
        case '\\': out += '\\'; break;
        case '/': out += '/'; break;
        case 'b': out += '\b'; break;
        case 'f': out += '\f'; break;
        case 'n': out += '\n'; break;
        case 'r': out += '\r'; break;
        case 't': out += '\t'; break;
        case 'u': {
          const hi = this.hex4();
          if (hi >= 0xd800 && hi <= 0xdbff) {
            // AR-6: a high surrogate escape must be completed by a low surrogate escape
            if (this.s[this.i] !== '\\' || this.s[this.i + 1] !== 'u') this.fail('lone high surrogate');
            this.i += 2;
            const lo = this.hex4();
            if (lo < 0xdc00 || lo > 0xdfff) this.fail('lone high surrogate');
            out += String.fromCharCode(hi, lo);
          } else if (hi >= 0xdc00 && hi <= 0xdfff) {
            this.fail('lone low surrogate'); // AR-6
          } else {
            out += String.fromCharCode(hi);
          }
          break;
        }
        default:
          this.fail('bad escape');
      }
    }
  }
}
