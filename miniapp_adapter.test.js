"use strict";

const assert = require("node:assert/strict");
const { createCipheriv, createDecipheriv, createHmac, createHash } = require("node:crypto");
const { test } = require("node:test");
const { createAdapter, parseCredential } = require("./miniapp_adapter");

const rawKey = Buffer.alloc(16, 1);
const rawIv = Buffer.alloc(16, 2);
const key = {
  type: "wechat_official",
  encryptKey: rawKey.toString("base64"),
  iv: rawIv.toString("base64"),
  version: 2,
  expireAt: Date.now() + 3600000
};
const credential = { token: "fake-token", key };
const base = "https://icq.cqust.edu.cn/icqust-admin";

function decrypt(ciphertext) {
  const decipher = createDecipheriv("aes-128-cbc", rawKey, rawIv);
  return JSON.parse(Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final()
  ]).toString());
}

function encryptedResponse(data, secret) {
  const cipher = createCipheriv("aes-128-cbc", rawKey, rawIv);
  const encData = Buffer.concat([
    cipher.update(JSON.stringify(data)), cipher.final()
  ]).toString("base64");
  return {
    statusCode: 200,
    data: {
      code: 200,
      encData,
      mac: createHmac("sha256", secret).update(encData).digest("hex")
    }
  };
}

test("locates original modules and uses original GET signing/decryption", async () => {
  const calls = [];
  const secret = "dummy-secret";
  const adapter = createAdapter({
    credential,
    transport: async request => {
      calls.push(request);
      if (request.url === base + "/wechat/checkToken") {
        assert.equal(request.method, "GET");
        assert.equal(request.header.Authorization, "Bearer fake-token");
        return { statusCode: 200, data: { code: 200, data: { signSecret: secret } } };
      }
      assert.equal(request.url, base + "/wechat/checkIn/myCourses");
      assert.equal(request.method, "GET");
      assert.equal(request.header["X-Encrypt-Type"], "wechat_official");
      assert.equal(request.header["X-Enc-Version"], "2");
      assert.equal(request.header["X-Body-Hash"], "");
      const { "X-Timestamp": time, "X-Nonce": nonce, "X-Sign": signature } = request.header;
      assert.equal(signature, createHmac("sha256", secret)
        .update(`GET|/wechat/checkIn/myCourses|||${time}|${nonce}|${secret}`).digest("hex"));
      return encryptedResponse([{ name: "dummy-course" }], secret);
    }
  });
  assert.equal(adapter.moduleCount, 103);
  const courses = await adapter.courses();
  assert.equal(courses.code, 200);
  assert.equal(JSON.stringify(courses.data), '[{"name":"dummy-course"}]');
  assert.deepEqual(calls.map(item => item.url), [
    base + "/wechat/checkToken", base + "/wechat/checkIn/myCourses"
  ]);
});

test("original POST encrypts body, signs ciphertext, and decrypts response", async () => {
  const requests = [];
  const secret = "dummy-secret";
  const adapter = createAdapter({
    credential, allowSend: true,
    transport: async request => {
      requests.push(request);
      if (request.url.endsWith("/checkToken")) {
        return { statusCode: 200, data: { code: 200, data: { signSecret: secret } } };
      }
      assert.equal(request.method, "POST");
      assert.equal(request.url, base + "/wechat/checkIn/checkInWithLocation");
      assert.deepEqual(decrypt(request.data.encData), {
        cnum: "course-teacher-123456", location: "纬度:1经度:2"
      });
      const hash = createHash("md5").update(request.data.encData).digest("hex").slice(0, 16);
      assert.equal(request.header["X-Body-Hash"], hash);
      const { "X-Timestamp": time, "X-Nonce": nonce, "X-Sign": signature } = request.header;
      assert.equal(signature, createHmac("sha256", secret)
        .update(`POST|/wechat/checkIn/checkInWithLocation||${hash}|${time}|${nonce}|${secret}`).digest("hex"));
      return encryptedResponse({ msg: "dummy-ok" }, secret);
    }
  });
  const result = await adapter.checkin("course-teacher-123456", "纬度:1经度:2");
  assert.equal(result.code, 200);
  assert.equal(JSON.stringify(result.data), '{"msg":"dummy-ok"}');
  assert.equal(requests.length, 2);
});

test("does not send checkin without explicit allowSend, and rejects expired key", () => {
  const adapter = createAdapter({ credential, transport: () => { throw new Error("network used"); } });
  assert.throws(() => adapter.checkin("c", "l"), /未启用/);
  assert.throws(() => createAdapter({
    credential: { token: "fake", key: { ...key, expireAt: Date.now() - 1 } }
  }), /已过期/);
  assert.throws(() => parseCredential("fake#WX96KEY#bad"), /JSON/);
});

test("original signature failure fetches a new secret and retries", async () => {
  let checks = 0;
  let courses = 0;
  const adapter = createAdapter({
    credential,
    transport: async request => {
      if (request.url.endsWith("/checkToken")) {
        checks++;
        return {
          statusCode: 200,
          data: { code: 200, data: { signSecret: `dummy-secret-${checks}` } }
        };
      }
      courses++;
      const secret = `dummy-secret-${checks}`;
      const { "X-Timestamp": time, "X-Nonce": nonce, "X-Sign": signature } = request.header;
      assert.equal(signature, createHmac("sha256", secret)
        .update(`GET|/wechat/checkIn/myCourses|||${time}|${nonce}|${secret}`).digest("hex"));
      if (courses === 1) return { statusCode: 401, data: { code: 4011, msg: "invalid signature" } };
      return encryptedResponse([], secret);
    }
  });
  assert.equal((await adapter.courses()).code, 200);
  assert.equal(checks, 2);
  assert.equal(courses, 2);
});

test("original request rejects network failures without leaking credential", async () => {
  const adapter = createAdapter({
    credential,
    transport: async () => { throw new Error("offline"); }
  });
  await assert.rejects(adapter.courses());
});
