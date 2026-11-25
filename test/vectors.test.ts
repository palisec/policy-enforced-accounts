import { readFileSync } from "node:fs";
import { hashTypedData } from "viem";
import { describe, expect, it } from "vitest";
import {
  canonicalize,
  decodeReason,
  fetchPolicy,
  encodeReason,
  intentHash,
  intentHashV1,
  INTERFACE_ID,
  PALISEC_REASON_MAP,
  policyHash,
  REASONS,
  REGISTRY_V1_ADDRESSES,
  recoverReceiptSigner,
  typedReceipt,
  verifyReceipt,
  type ReceiptJson,
} from "../src";

const V = JSON.parse(readFileSync(new URL("../vectors/vectors.json", import.meta.url), "utf8"));
const V1 = JSON.parse(readFileSync(new URL("../vectors/vectors-v1.json", import.meta.url), "utf8"));

describe("JCS (RFC 8785)", () => {
  it("matches the RFC 8785 section 3.2.2 example", () => {
    const input = JSON.parse(
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
    );
    expect(canonicalize(input)).toBe('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}');
  });
  it("sorts keys by UTF-16 code units", () => {
    expect(canonicalize({ "\u20ac": 1, "\r": 2, "\ufb33": 3, "1": 4, "\u{1f600}": 5, "\u0080": 6, "\u00f6": 7 })).toBe(
      '{"\\r":2,"1":4,"\u0080":6,"ö":7,"€":1,"\u{1f600}":5,"\ufb33":3}',
    );
  });
  it("rejects non-JSON values", () => {
    expect(() => canonicalize({ a: Number.NaN })).toThrow();
    expect(() => canonicalize({ a: () => 1 })).toThrow();
  });
  for (const p of V.policies)
    it(`policy vector: ${p.name}`, () => {
      expect(canonicalize(p.document)).toBe(p.jcs);
      expect(policyHash(p.document)).toBe(p.policyHash);
    });
});

describe("intents", () => {
  for (const i of V.intents) it(i.name, () => expect(intentHash(i.intent)).toBe(i.intentHash));
  it("a call and a delegatecall to the same target and data differ", () => {
    expect(V.intents[1].intent.data).toBe(V.intents[2].intent.data);
    expect(intentHash(V.intents[1].intent)).not.toBe(intentHash(V.intents[2].intent));
    expect(intentHash({ ...V.intents[1].intent, operation: undefined })).toBe(V.intents[1].intentHash);
    expect(() => intentHash({ ...V.intents[1].intent, operation: 256 })).toThrow();
  });
  it("the vectors name the v2 interface", () => expect(V.interfaceId).toBe(INTERFACE_ID));
  it("any field change changes the hash", () => {
    const i = V.intents[0].intent;
    expect(intentHash({ ...i, value: "20000000000001" })).not.toBe(V.intents[0].intentHash);
    expect(intentHash({ ...i, chainId: 46630 })).not.toBe(V.intents[0].intentHash);
  });
});

describe("receipts", () => {
  for (const r of V.receipts)
    it(r.name, async () => {
      const receipt = r.receipt as ReceiptJson;
      expect(hashTypedData(typedReceipt(receipt))).toBe(r.digest);
      expect(await recoverReceiptSigner(receipt)).toBe(V.testKeys.receiptSigner.address);
      expect(encodeReason(receipt.reasonCode)).toBe(r.encodedReason);
      expect(decodeReason(r.encodedDetail)).toBe(receipt.detailCode);
    });
  it("a tampered receipt recovers a different signer", async () => {
    const r = { ...(V.receipts[1].receipt as ReceiptJson), decision: "ALLOW" as const };
    expect(await recoverReceiptSigner(r)).not.toBe(V.testKeys.receiptSigner.address);
  });
});

describe("first-draft (v1) vectors still verify", () => {
  for (const i of V1.intents) it(`v1 intent: ${i.name}`, () => expect(intentHashV1(i.intent)).toBe(i.intentHash));
  for (const r of V1.receipts)
    it(`v1 receipt: ${r.name}`, async () => {
      const receipt = r.receipt as ReceiptJson;
      expect(hashTypedData(typedReceipt(receipt, "1"))).toBe(r.digest);
      expect(await recoverReceiptSigner(receipt, "1")).toBe(V1.testKeys.receiptSigner.address);
    });
  it("a v1 receipt does not verify under the v2 domain", async () => {
    expect(await recoverReceiptSigner(V1.receipts[0].receipt as ReceiptJson, "2")).not.toBe(V1.testKeys.receiptSigner.address);
  });
});

describe("acting on a receipt (use-time rules)", () => {
  const receipt = V.receipts[0].receipt as ReceiptJson; // ALLOW, policy version 3
  const intent = V.intents[0].intent;
  const now = BigInt(receipt.issuedAt) + 10n;
  const client = (over: { version?: bigint; hash?: string; stopped?: boolean } = {}) =>
    ({
      getChainId: async () => 4663,
      getBlock: async () => ({ timestamp: now }),
      getCode: async () => "0x",
      readContract: async ({ functionName }: { functionName: string }) => {
        if (functionName === "signersAt" || functionName === "policySigner") return { receiptSigner: V.testKeys.receiptSigner.address };
        if (functionName === "policyOf") return { policyHash: over.hash ?? receipt.policyHash, version: over.version ?? 3n, effectiveAt: 0n, policyURI: "", schemaURI: "" };
        if (functionName === "isStopped") return over.stopped ?? false;
        throw new Error(functionName);
      },
    }) as never;
  const store = (seen = new Set<string>()) => ({ claim: (id: string) => (seen.has(id) ? false : (seen.add(id), true)) });
  const opts = (seen = new Set<string>()) => ({ registry: receipt.registry, intent, now, use: true, seen: store(seen) });

  it("passes once, then refuses the same decisionId", async () => {
    const o = opts();
    expect((await verifyReceipt(client(), receipt, o)).valid).toBe(true);
    const again = await verifyReceipt(client(), receipt, o);
    expect(again.valid).toBe(false);
    expect(again.problems).toContain("decisionId was already used");
  });
  it("a refused receipt does not use up its decisionId", async () => {
    const used = new Set<string>();
    expect((await verifyReceipt(client({ stopped: true }), receipt, opts(used))).valid).toBe(false);
    expect(used.size).toBe(0);
    expect((await verifyReceipt(client(), receipt, opts(used))).valid).toBe(true);
  });
  it("parallel checks of one receipt: only one passes", async () => {
    const o = opts();
    const results = await Promise.all([1, 2, 3, 4].map(() => verifyReceipt(client(), receipt, o)));
    expect(results.filter((r) => r.valid)).toHaveLength(1);
  });
  it("refuses a receipt whose policy is no longer the current one", async () => {
    const r = await verifyReceipt(client({ version: 4n }), receipt, opts());
    expect(r.valid).toBe(false);
    expect(r.problems.join()).toMatch(/not the current policy/);
    expect((await verifyReceipt(client({ hash: `0x${"1".repeat(64)}` }), receipt, opts())).valid).toBe(false);
  });
  it("refuses while the account is stopped", async () => {
    const r = await verifyReceipt(client({ stopped: true }), receipt, opts());
    expect(r.problems).toContain("the account's emergency stop is engaged");
  });
  it("refuses a DENY, and needs the intent", async () => {
    expect((await verifyReceipt(client(), V.receipts[1].receipt as ReceiptJson, opts())).valid).toBe(false);
    const { intent: _i, ...noIntent } = opts();
    expect((await verifyReceipt(client(), receipt, noIntent)).problems).toContain("acting on a receipt requires the intent it must be bound to");
  });
  it("a receipt issued under the v1 registry is never acted on", async () => {
    const v1 = { ...receipt, registry: REGISTRY_V1_ADDRESSES[4663]! };
    const r = await verifyReceipt(client(), v1, { ...opts(), registry: v1.registry });
    expect(r.valid).toBe(false);
    expect(r.problems.join()).toMatch(/audits only/);
  });
  it("an audit (no use) keeps the first draft rules", async () => {
    expect((await verifyReceipt(client({ version: 9n, stopped: true }), receipt, { registry: receipt.registry, intent, now })).valid).toBe(true);
  });
});

describe("reason codes", () => {
  it("every code fits in bytes32 and round-trips", () => {
    for (const c of Object.keys(REASONS)) expect(decodeReason(encodeReason(c))).toBe(c);
    expect(decodeReason(encodeReason("NONE"))).toBe("NONE");
  });
  it("maps every Palisec code to a standard code", () => {
    for (const v of Object.values(PALISEC_REASON_MAP)) expect(REASONS).toHaveProperty(v);
    expect(Object.keys(PALISEC_REASON_MAP)).toHaveLength(26);
  });
});

describe("fetchPolicy guards", () => {
  const c = (policyURI: string) => ({ policyHash: V.policies[4].policyHash, version: 3n, effectiveAt: 0n, policyURI, schemaURI: "" });
  const never = (() => {
    throw new Error("must not fetch");
  }) as unknown as typeof fetch;
  it("refuses non-https and private hosts without fetching", async () => {
    await expect(fetchPolicy(c("http://example.com/p"), never)).rejects.toThrow("https");
    await expect(fetchPolicy(c("https://localhost/p"), never)).rejects.toThrow("private");
    await expect(fetchPolicy(c("https://10.0.0.1/p"), never)).rejects.toThrow("private");
    await expect(fetchPolicy(c("https://[::1]/p"), never)).rejects.toThrow("private");
  });
  it("checks the document against the committed hash", async () => {
    const doc = V.policies[4].document;
    const ok = (async () => new Response(JSON.stringify(doc), { status: 200 })) as unknown as typeof fetch;
    expect((await fetchPolicy(c("https://example.com/p"), ok)).matches).toBe(true);
    const bad = (async () => new Response(JSON.stringify({ ...doc, version: 4 }), { status: 200 })) as unknown as typeof fetch;
    expect((await fetchPolicy(c("https://example.com/p"), bad)).matches).toBe(false);
  });
});

describe("fetchPolicy limits", () => {
  it("stops reading past 1 MB even without content-length", async () => {
    const big = (async () => new Response(new ReadableStream({ pull(c) { c.enqueue(new Uint8Array(256 * 1024).fill(32)); } }), { status: 200 })) as unknown as typeof fetch;
    await expect(fetchPolicy({ policyHash: V.policies[4].policyHash, version: 3n, effectiveAt: 0n, policyURI: "https://example.com/p", schemaURI: "" }, big)).rejects.toThrow("too large");
  });
  it("refuses CGNAT and IPv4-mapped IPv6 literals", async () => {
    const never = (() => { throw new Error("must not fetch"); }) as unknown as typeof fetch;
    const c = (u: string) => ({ policyHash: V.policies[4].policyHash, version: 3n, effectiveAt: 0n, policyURI: u, schemaURI: "" });
    await expect(fetchPolicy(c("https://100.64.0.1/p"), never)).rejects.toThrow("private");
    await expect(fetchPolicy(c("https://[::ffff:7f00:1]/p"), never)).rejects.toThrow("private");
  });
});

describe("registry v3 interface", () => {
  it("INTERFACE_ID is the XOR of the eight read selectors (v2's seven plus stopHeldByAccount)", async () => {
    const { toFunctionSelector } = await import("viem");
    const { INTERFACE_ID: V3, INTERFACE_ID_V2: V2 } = await import("../src/abi");
    const reads = ["policySigner(address)", "signersAt(address,uint64)", "pendingSignersOf(address)", "policyOf(address)", "pendingPolicyOf(address)", "mandateOf(address)", "isStopped(address)"];
    const id = (sigs: string[]) => "0x" + (sigs.reduce((a, s) => (a ^ parseInt(toFunctionSelector(s).slice(2), 16)) >>> 0, 0) >>> 0).toString(16).padStart(8, "0");
    expect(id(reads)).toBe(V2);
    expect(id([...reads, "stopHeldByAccount(address)"])).toBe(V3);
  });
});
