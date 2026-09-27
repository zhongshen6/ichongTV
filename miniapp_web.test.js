"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { once } = require("node:events");
const { createWebServer } = require("./miniapp_web");

test("serves the HTML and routes only permitted same-origin operations", async () => {
  const calls = [];
  const server = createWebServer({
    adapterFactory(options) {
      calls.push(options);
      return {
        courses: async () => ({ code: 200, data: [] }),
        checkin: async (cnum, location) => ({ code: 200, data: { cnum, location } })
      };
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const origin = `http://127.0.0.1:${server.address().port}`;
  try {
    const page = await fetch(origin);
    assert.equal(page.status, 200);
    assert.match(await page.text(), /courseSelect/);
    const request = (path, payload, override = {}) => fetch(origin + path, {
      method: "POST",
      headers: { Origin: origin, "Content-Type": "application/json", ...override },
      body: JSON.stringify(payload)
    });
    const credential = "fake#WX96KEY#{}";
    const courses = await request("/api/courses", { credential });
    assert.equal((await courses.json()).body.code, 200);
    assert.equal(calls[0].allowSend, false);
    const missingConfirmation = await request("/api/checkin", {
      credential, cnum: "c", location: "l"
    });
    assert.equal(missingConfirmation.status, 400);
    assert.equal(calls.length, 1);
    const checkin = await request("/api/checkin", {
      credential, cnum: "c", location: "l", confirmSend: true
    });
    assert.equal((await checkin.json()).body.data.cnum, "c");
    assert.equal(calls[1].allowSend, true);
    assert.equal((await request("/api/checkin", {
      credential, cnum: "c", location: "l", confirmSend: true
    }, { Origin: "http://evil.invalid" })).status, 403);
    assert.equal((await fetch(origin + "/api/courses")).status, 404);
    assert.equal(calls.length, 2);
  } finally {
    server.close();
    await once(server, "close");
  }
});
