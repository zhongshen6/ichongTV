"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const vm = require("node:vm");
const { createCipheriv, createDecipheriv, createHash, createHmac } = require("node:crypto");
const { test } = require("node:test");
const { build } = require("./update_miniapp_bundle");

const rawKey = Buffer.alloc(16, 1);
const rawIv = Buffer.alloc(16, 2);
const key = {
  type: "wechat_official",
  encryptKey: rawKey.toString("base64"),
  iv: rawIv.toString("base64"),
  version: 2,
  expireAt: Date.now() + 3600000
};
const account = { token: "fake-token", cryptoKey: key };

function encryptedResponse(data, secret) {
  const cipher = createCipheriv("aes-128-cbc", rawKey, rawIv);
  const encData = Buffer.concat([cipher.update(JSON.stringify(data)), cipher.final()])
    .toString("base64");
  return {
    code: 200,
    encData,
    mac: createHmac("sha256", secret).update(encData).digest("hex")
  };
}

test("generated area is reproducible and calls original browser request chain", async () => {
  const { html, updated, count } = build();
  assert.equal(html, updated);
  assert.ok(count >= 4);
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)][0][1];
  const calls = [];
  const secret = "dummy-secret";
  const context = vm.createContext({
    URL, AbortSignal, setTimeout, clearTimeout,
    fetch: async (url, options) => {
      calls.push({ url, options });
      if (url.endsWith("/checkToken")) {
        return { status: 200, json: async () => ({
          code: 200, data: { signSecret: secret }
        }) };
      }
      assert.equal(options.headers["X-Encrypt-Type"], "wechat_official");
      const path = new URL(url).pathname.slice("/icqust-admin".length);
      const hash = options.method === "POST"
        ? createHash("md5").update(JSON.parse(options.body).encData).digest("hex").slice(0, 16)
        : "";
      const { "X-Timestamp": time, "X-Nonce": nonce, "X-Sign": sign } = options.headers;
      assert.equal(options.headers["X-Body-Hash"], hash);
      assert.equal(sign, createHmac("sha256", secret)
        .update(`${options.method}|${path}||${hash}|${time}|${nonce}|${secret}`).digest("hex"));
      if (options.method === "POST") {
        const encData = JSON.parse(options.body).encData;
        const decipher = createDecipheriv("aes-128-cbc", rawKey, rawIv);
        assert.deepEqual(JSON.parse(Buffer.concat([
          decipher.update(Buffer.from(encData, "base64")), decipher.final()
        ]).toString()), { cnum: "course-123456", location: "纬度:1经度:2" });
      }
      return {
        status: 200,
        json: async () => encryptedResponse(options.method === "GET" ? [] : { msg: "ok" }, secret)
      };
    }
  });
  vm.runInContext(script, context, { timeout: 5000 });
  const runtime = vm.runInContext("Wx96Miniapp", context);
  const client = runtime.createClient(account);
  assert.equal((await client.courses()).code, 200);
  assert.equal((await client.checkin("course-123456", "纬度:1经度:2")).code, 200);
  assert.deepEqual(calls.map(call => new URL(call.url).pathname), [
    "/icqust-admin/wechat/checkToken",
    "/icqust-admin/wechat/checkIn/myCourses",
    "/icqust-admin/wechat/checkIn/checkInWithLocation"
  ]);
});

test("expired key cannot trigger a browser request", () => {
  const html = fs.readFileSync("wx96_checkin_tool.html", "utf8");
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)][0][1];
  const context = vm.createContext({ URL, AbortSignal, setTimeout, clearTimeout });
  vm.runInContext(script, context, { timeout: 5000 });
  assert.throws(() => vm.runInContext("Wx96Miniapp", context).createClient({
    ...account, cryptoKey: { ...key, expireAt: Date.now() - 1 }
  }), /key/);
});

test("embedded original request refreshes signature and retries", async () => {
  const html = fs.readFileSync("wx96_checkin_tool.html", "utf8");
  const script = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)][0][1];
  let secrets = 0;
  let courses = 0;
  const context = vm.createContext({
    URL, AbortSignal, setTimeout, clearTimeout,
    fetch: async (url, options) => {
      if (url.endsWith("/checkToken")) {
        secrets++;
        return { status: 200, json: async () => ({
          code: 200, data: { signSecret: `dummy-${secrets}` }
        }) };
      }
      courses++;
      const secret = `dummy-${secrets}`;
      const { "X-Timestamp": time, "X-Nonce": nonce, "X-Sign": sign } = options.headers;
      assert.equal(sign, createHmac("sha256", secret)
        .update(`GET|/wechat/checkIn/myCourses|||${time}|${nonce}|${secret}`).digest("hex"));
      return courses === 1
        ? { status: 401, json: async () => ({ code: 4011, msg: "invalid signature" }) }
        : { status: 200, json: async () => encryptedResponse([], secret) };
    }
  });
  vm.runInContext(script, context, { timeout: 5000 });
  const client = vm.runInContext("Wx96Miniapp", context).createClient(account);
  assert.equal((await client.courses()).code, 200);
  assert.equal(secrets, 2);
  assert.equal(courses, 2);
});
