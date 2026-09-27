"use strict";

const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const { createAdapter } = require("./miniapp_adapter");

const html = fs.readFileSync(path.join(__dirname, "wx96_checkin_tool.html"));

function createWebServer({ adapterFactory = createAdapter } = {}) {
  const server = http.createServer(async (req, res) => {
    const address = server.address();
    const origin = `http://127.0.0.1:${address.port}`;
    const headers = {
      "Cache-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Content-Type-Options": "nosniff"
    };
    function json(status, body) {
      res.writeHead(status, { ...headers, "Content-Type": "application/json; charset=utf-8" });
      res.end(JSON.stringify(body));
    }
    if (req.headers.host !== `127.0.0.1:${address.port}`) {
      return json(403, { error: "仅允许本机访问" });
    }
    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { ...headers, "Content-Type": "text/html; charset=utf-8" });
      return res.end(html);
    }
    if (req.method !== "POST" ||
        !["/api/courses", "/api/checkin"].includes(req.url)) {
      return json(404, { error: "接口不存在" });
    }
    if (req.headers.origin !== origin ||
        !/^application\/json(?:\s*;|$)/i.test(req.headers["content-type"] || "")) {
      return json(403, { error: "请求来源不正确" });
    }
    let text = "";
    try {
      for await (const chunk of req) {
        text += chunk;
        if (text.length > 65536) return json(413, { error: "请求过大" });
      }
      const payload = JSON.parse(text);
      if (!payload || typeof payload.credential !== "string") {
        return json(400, { error: "缺少 Credential" });
      }
      const send = req.url === "/api/checkin";
      if (send && (!payload.confirmSend ||
          typeof payload.cnum !== "string" || typeof payload.location !== "string")) {
        return json(400, { error: "签到参数或确认缺失" });
      }
      const adapter = adapterFactory({ credential: payload.credential, allowSend: send });
      const body = send
        ? await adapter.checkin(payload.cnum, payload.location)
        : await adapter.courses();
      return json(200, { status: 200, ok: [0, 200].includes(Number(body?.code)), body });
    } catch (error) {
      return json(400, {
        error: error?.message && !(error?.data || error?.statusCode)
          ? error.message : "原版请求失败，请检查凭据、网络和小程序版本"
      });
    }
  });
  return server;
}

if (require.main === module) {
  const server = createWebServer();
  const port = Number(process.env.PORT) || 8787;
  server.on("error", error => {
    if (error.code === "EADDRINUSE") server.listen(0, "127.0.0.1");
    else {
      console.error(error.message);
      process.exitCode = 1;
    }
  });
  server.listen(port, "127.0.0.1", () => {
    console.log(`本地页面：http://127.0.0.1:${server.address().port}/`);
  });
}

module.exports = { createWebServer };
