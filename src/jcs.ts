import jcs from "canonicalize";
import { keccak256, toBytes, type Hex } from "viem";

/** Only JSON values: anything a policy document can't contain is rejected, never silently dropped. */
function assertJson(value: unknown): void {
  if (value === null) return;
  switch (typeof value) {
    case "boolean":
    case "string":
      return;
    case "number":
      if (!Number.isFinite(value)) throw new Error("JCS: non-finite number");
      return;
    case "object":
      if (Array.isArray(value)) return value.forEach(assertJson);
      for (const v of Object.values(value as Record<string, unknown>)) if (v !== undefined) assertJson(v);
      return;
    default:
      throw new Error(`JCS: cannot canonicalize ${typeof value}`);
  }
}

/**
 * RFC 8785 (JSON Canonicalization Scheme), by the reference implementation (`canonicalize`): objects with
 * keys sorted by UTF-16 code units, arrays in order, ECMAScript number serialization, minimal string escaping.
 * Non-finite numbers and non-JSON values are rejected.
 */
export function canonicalize(value: unknown): string {
  assertJson(value);
  const out = jcs(value);
  if (out === undefined) throw new Error("JCS: value has no JSON form");
  return out;
}

/** policyHash = keccak256 of the UTF-8 bytes of the document's JCS form. */
export function policyHash(document: unknown): Hex {
  return keccak256(toBytes(canonicalize(document)));
}
