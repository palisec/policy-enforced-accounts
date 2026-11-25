// Generates vectors/vectors.json (v2: intents with the operation, EIP-712 domain version "2") from the built
// library (pnpm build first). The first draft's set stays in vectors/vectors-v1.json. Keys are TEST-ONLY:
// keccak256 of fixed labels, published so anyone can reproduce every signature. Never fund them.
import { writeFileSync } from "node:fs";
import { hashTypedData, keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { canonicalize, encodeReason, intentHash, policyHash, typedReceipt } from "../dist/index.js";

const key = (label) => keccak256(stringToHex(`policy-enforced-accounts test vector key: ${label}`));
const receiptKey = key("receipt signer 1");
const signer = privateKeyToAccount(receiptKey);
const REGISTRY = "0x00000000000000000000000000000000000000Aa";
const ACCOUNT = "0x1111111111111111111111111111111111111111";

const policies = [
  { name: "empty object", document: {} },
  { name: "key order and nesting", document: { b: 1, a: { d: [3, 2, 1], c: "x" } } },
  { name: "unicode and escaping", document: { "é": "€", "a\"b": "line\nbreak", "\u0001": true, z: null } },
  { name: "numbers", document: { int: 100, neg: -5, zero: 0, float: 1.5, big: 1e21, small: 1e-7 } },
  {
    name: "minimal common core policy",
    document: {
      schema: "https://palisec.tech/schemas/peaa-core-1.json",
      account: { chain_id: 4663, address: ACCOUNT },
      version: 3,
      limits: { max_transaction_value_wei: "300000000000000", rolling_budget_usd_micros: "2000000", rolling_window_seconds: 3600 },
      contracts: { default: "deny", allowlist: [{ address: "0x2222222222222222222222222222222222222222", selectors: ["0xa9059cbb"] }], denylist: [] },
      human_approval: { usd_threshold_micros: "500000" },
      loosening_delay_seconds: 3600,
      failure_mode: "closed",
    },
  },
].map((p) => ({ ...p, jcs: canonicalize(p.document), policyHash: policyHash(p.document) }));

const intents = [
  { name: "native transfer", intent: { chainId: 4663, account: ACCOUNT, target: "0x2222222222222222222222222222222222222222", value: "20000000000000", data: "0x", operation: 0 } },
  { name: "token transfer call", intent: { chainId: 4663, account: ACCOUNT, target: "0x2222222222222222222222222222222222222222", value: "0", data: "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a", operation: 0 } },
  { name: "same call as a delegatecall", intent: { chainId: 4663, account: ACCOUNT, target: "0x2222222222222222222222222222222222222222", value: "0", data: "0xa9059cbb0000000000000000000000003333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000a", operation: 1 } },
].map((i) => ({ ...i, intentHash: intentHash(i.intent) }));

const base = { chainId: "4663", registry: REGISTRY, account: ACCOUNT, policyHash: policies[4].policyHash, policyVersion: "3", issuedAt: "1800000000", expiresAt: "1800000300" };
const receipts = [];
for (const [name, decision, reasonCode, detailCode, intent] of [
  ["allow", "ALLOW", "NONE", "NONE", intents[0]],
  ["deny over limit", "DENY", "OVER_LIMIT", "palisec:PS_BUDGET_001", intents[0]],
  ["review: human approval", "REVIEW", "HUMAN_APPROVAL_REQUIRED", "palisec:PS_HUMAN_001", intents[1]],
  ["deny: delegatecall not allowed", "DENY", "METHOD_NOT_ALLOWED", "palisec:PS_METHOD_001", intents[2]],
]) {
  const r = { ...base, intentHash: intent.intentHash, decision, reasonCode, detailCode, decisionId: keccak256(stringToHex(`decision ${name}`)), signer: signer.address };
  const typed = typedReceipt({ ...r, signature: "0x" }, "2");
  const signature = await signer.signTypedData(typed);
  receipts.push({ name, receipt: { ...r, signature }, digest: hashTypedData(typed), encodedReason: encodeReason(reasonCode), encodedDetail: encodeReason(detailCode) });
}
const out = {
  description: "Test vectors for the draft ERC Policy-Enforced Agent Accounts. Keys are test-only and public; never fund them.",
  version: 2,
  domain: { name: "PolicyDecisionReceipt", version: "2" },
  interfaceId: "0xf594edcd",
  testKeys: { receiptSigner: { privateKey: receiptKey, address: signer.address, label: "policy-enforced-accounts test vector key: receipt signer 1" } },
  policies,
  intents,
  receipts,
};
writeFileSync(new URL("../vectors/vectors.json", import.meta.url), JSON.stringify(out, null, 2) + "\n");
console.log("vectors:", policies.length, "policies,", intents.length, "intents,", receipts.length, "receipts; signer", signer.address);
