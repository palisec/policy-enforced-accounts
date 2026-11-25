// End-to-end on a local chain (anvil): deploy the reference registry v3, declare, publish through the delay,
// then read and verify with the library only. Uses anvil's public test accounts.
// Run: anvil &; node scripts/local-chain-check.mjs
import { readFileSync } from "node:fs";
import { createPublicClient, createTestClient, createWalletClient, defineChain, http, keccak256, stringToHex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { REGISTRY_ABI, intentHash, policyHash, readAccount, typedReceipt, verifyReceipt } from "../dist/index.js";

const RPC = process.env.RPC ?? "http://127.0.0.1:8545";
const chain = defineChain({ id: 31337, name: "anvil", nativeCurrency: { name: "ETH", symbol: "ETH", decimals: 18 }, rpcUrls: { default: { http: [RPC] } } });
const pub = createPublicClient({ chain, transport: http(RPC) });
const test = createTestClient({ chain, mode: "anvil", transport: http(RPC) });
// anvil's well-known test keys (public; never use on a real chain)
const K = ["0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80", "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d", "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"];
const [accountKey, publisherKey, receiptKey] = K.map((k) => privateKeyToAccount(k));
const w = (a) => createWalletClient({ account: a, chain, transport: http(RPC) });
const art = JSON.parse(readFileSync(new URL("../contracts/out/PolicyEnforcedRegistry.sol/PolicyEnforcedRegistry.json", import.meta.url), "utf8"));
let ok = 0, bad = 0;
const check = (name, cond, extra = "") => { cond ? ok++ : bad++; console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  " + extra}`); };
const DELAY = 900;
const later = async (s) => { await test.increaseTime({ seconds: s }); await test.mine({ blocks: 1 }); };
const nowB = async () => (await pub.getBlock()).timestamp;

const hash = await w(accountKey).deployContract({ abi: REGISTRY_ABI, bytecode: art.bytecode.object });
const registry = (await pub.waitForTransactionReceipt({ hash })).contractAddress;
const account = accountKey.address; // the "account" declares itself (a Safe would do this through a Safe transaction)
const send = async (who, functionName, args) => pub.waitForTransactionReceipt({ hash: await w(who).writeContract({ address: registry, abi: REGISTRY_ABI, functionName, args }) });
const reverts = async (who, functionName, args) => {
  try {
    await pub.simulateContract({ account: who, address: registry, abi: REGISTRY_ABI, functionName, args });
    return null;
  } catch (e) {
    return e.cause?.data?.errorName ?? e.shortMessage ?? "reverted";
  }
};

let st = await readAccount(pub, account, registry);
check("undeclared account reads as not enforced (v2 source)", st.enforced === false && st.policy === null && st.standard === "v3");
await send(accountKey, "declare", [accountKey.address, publisherKey.address, receiptKey.address, DELAY, 1]);
st = await readAccount(pub, account, registry);
check("first declaration applies at once, with minDelay and signerType", st.enforced && st.publisher === publisherKey.address && st.minDelay === DELAY && st.signerType === 1);

const doc = { account: { chain_id: 31337, address: account }, version: 1, limits: { max_transaction_value_wei: "1000" } };
const h = policyHash(doc);
check("the publisher cannot activate a new version at once", (await reverts(publisherKey, "activate", [account, h, 1n, "", ""])) === "NoPending");
check("a pending change sooner than minDelay is refused", (await reverts(publisherKey, "setPending", [account, h, 1n, (await nowB()) + 60n, "", ""])) === "TooSoon");
let at = (await nowB()) + BigInt(DELAY) + 5n;
await send(publisherKey, "setPending", [account, h, 1n, at, "", "https://example.invalid/schema.json"]);
st = await readAccount(pub, account, registry);
check("pending policy visible, nothing decides yet", st.pending?.policyHash === h && st.policy === null);
check("confirming early is refused", (await reverts(publisherKey, "activate", [account, h, 1n, "", ""])) === "NotDue");
await later(DELAY + 10);
st = await readAccount(pub, account, registry);
check("after the delay the policy decides, by time alone", st.policy?.policyHash === h && st.policy.version === 1n && st.policy.effectiveAt === at);
await send(publisherKey, "activate", [account, h, 1n, "", ""]);
check("confirmation keeps effectiveAt", (await readAccount(pub, account, registry)).policy?.effectiveAt === at);

const now = await nowB();
const intent = { chainId: 31337, account, target: "0x2222222222222222222222222222222222222222", value: 20n, data: "0x", operation: 0 };
const base = { chainId: "31337", registry, account, intentHash: intentHash(intent), policyHash: h, policyVersion: "1", issuedAt: String(now), expiresAt: String(now + 300n), signer: receiptKey.address, signature: "0x" };
const r = { ...base, decision: "DENY", reasonCode: "OVER_LIMIT", detailCode: "palisec:PS_BUDGET_001", decisionId: keccak256(stringToHex("local-1")) };
r.signature = await receiptKey.signTypedData(typedReceipt(r));
let v = await verifyReceipt(pub, r, { registry, intent, now });
check("genuine receipt verifies", v.valid, v.problems.join("; "));
v = await verifyReceipt(pub, { ...r, decision: "ALLOW" }, { registry, now });
check("tampered receipt is rejected", !v.valid);
v = await verifyReceipt(pub, r, { registry, intent: { ...intent, operation: 1 }, now });
check("the same call as a delegatecall is another intent", !v.valid);
v = await verifyReceipt(pub, r, { registry, now: now + 301n });
check("expired receipt is rejected", !v.valid);

const allow = { ...base, decision: "ALLOW", reasonCode: "NONE", detailCode: "NONE", decisionId: keccak256(stringToHex("local-allow")) };
allow.signature = await receiptKey.signTypedData(typedReceipt(allow));
const seen = new Set();
const store = { claim: (id) => (seen.has(id) ? false : (seen.add(id), true)) };
v = await verifyReceipt(pub, allow, { registry, intent, now, use: true, seen: store });
check("acting on an ALLOW for the current policy passes once", v.valid, v.problems.join("; "));
v = await verifyReceipt(pub, allow, { registry, intent, now, use: true, seen: store });
check("…and its decisionId cannot be used twice", !v.valid && v.problems.includes("decisionId was already used"));

const allow2 = { ...allow, decisionId: keccak256(stringToHex("local-allow-2")) };
allow2.signature = await receiptKey.signTypedData(typedReceipt(allow2));
await send(accountKey, "setStopped", [account, true, "key check"]);
v = await verifyReceipt(pub, allow2, { registry, intent, now, use: true, seen: store });
check("the account can stop itself, and a stopped account's ALLOW is refused", !v.valid && v.problems.includes("the account's emergency stop is engaged"));
check("the account's stop is held by the account", (await readAccount(pub, account, registry)).stopHeldByAccount === true);
check("the publisher cannot lift a stop the account engaged", (await reverts(publisherKey, "setStopped", [account, false, ""])) === "StopHeldByAccount");
await send(accountKey, "setStopped", [account, false, ""]);
check("the account lifts its own stop", (await readAccount(pub, account, registry)).stopped === false);
const doc2 = { ...doc, version: 2 };
await send(accountKey, "activate", [account, policyHash(doc2), 2n, "", ""]);
v = await verifyReceipt(pub, allow2, { registry, intent, now, use: true, seen: store });
check("an ALLOW for a policy that is no longer current is refused", !v.valid && v.problems.some((p) => p.includes("not the current policy")));

await send(accountKey, "declare", [accountKey.address, publisherKey.address, publisherKey.address, DELAY, 1]);
st = await readAccount(pub, account, registry);
check("a receipt-signer change waits minDelay", st.receiptSigner === receiptKey.address && st.pendingSigners?.receiptSigner === publisherKey.address);
v = await verifyReceipt(pub, r, { registry, now });
check("…so the current key's receipts still verify meanwhile", v.valid, v.problems.join("; "));
await later(DELAY + 1);
v = await verifyReceipt(pub, r, { registry, now });
check("after rotation, the old key's receipt is rejected by default", !v.valid);
v = await verifyReceipt(pub, r, { registry, now, allowRotatedSigner: true });
check("…and accepted for audits with allowRotatedSigner", v.valid, v.problems.join("; "));
console.log(`\n${ok} passed, ${bad} failed`);
process.exit(bad ? 1 : 0);
