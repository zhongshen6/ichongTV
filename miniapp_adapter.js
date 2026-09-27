"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = __dirname;
const BUNDLE_DIR = path.join(ROOT, "local_wxapkg", "wxapkg_out");
const APP_PREFIX = "wx96a1da8a627aa011_";
const EXPECTED_BASE = "https://icq.cqust.edu.cn/icqust-admin";
const COURSES = "/wechat/checkIn/myCourses";
const CHECKIN = "/wechat/checkIn/checkInWithLocation";
const CHECK_TOKEN = "/wechat/checkToken";
const SEPARATOR = "#WX96KEY#";

function latestBundle() {
  const candidates = fs.readdirSync(BUNDLE_DIR, { withFileTypes: true })
    .filter(item => item.isDirectory() && item.name.startsWith(APP_PREFIX))
    .map(item => ({
      version: Number(item.name.slice(APP_PREFIX.length)),
      file: path.join(BUNDLE_DIR, item.name, "appservice.app.js")
    }))
    .filter(item => Number.isInteger(item.version) && fs.existsSync(item.file))
    .sort((a, b) => b.version - a.version);
  if (!candidates.length) throw new Error("没有找到解包后的 appservice.app.js");
  return candidates[0].file;
}

function parseCredential(line) {
  const at = line.indexOf(SEPARATOR);
  if (at <= 0) throw new Error("凭据格式不正确，需要 CMD 输出的 Credential");
  const token = line.slice(0, at).trim();
  let key;
  try {
    key = JSON.parse(line.slice(at + SEPARATOR.length));
  } catch {
    throw new Error("crypto_key_info 不是有效 JSON");
  }
  if (!token || !key || typeof key !== "object" ||
      key.type !== "wechat_official" ||
      typeof key.encryptKey !== "string" || typeof key.iv !== "string") {
    throw new Error("凭据缺少 token 或有效的 crypto_key_info");
  }
  return { token, key };
}

function loadModules(bundle, wx) {
  const source = fs.readFileSync(bundle, "utf8");
  const begin = source.indexOf('define("');
  const end = source.lastIndexOf('require("app.js")');
  if (begin < 0 || end <= begin) throw new Error("未识别此版本的模块包装格式");
  const factories = new Map();
  const sandbox = {
    define(id, factory) {
      if (factories.has(id)) throw new Error("重复模块：" + id);
      factories.set(id, factory);
    },
    wx,
    console: { log() {}, warn() {}, error() {} },
    setTimeout,
    clearTimeout
  };
  vm.runInNewContext(source.slice(begin, end), sandbox, {
    filename: path.basename(bundle),
    timeout: 5000
  });
  const cache = new Map();
  function resolve(id) {
    if (cache.has(id)) return cache.get(id).exports;
    const factory = factories.get(id);
    if (!factory) throw new Error("解包模块缺失：" + id);
    const module = { exports: {} };
    cache.set(id, module);
    try {
      factory(resolve, module, module.exports);
      return module.exports;
    } catch (error) {
      cache.delete(id);
      throw error;
    }
  }
  function find(label, markers) {
    const found = [...factories].filter(([, factory]) =>
      markers.every(marker => factory.toString().includes(marker)));
    if (found.length !== 1) throw new Error(`无法唯一定位原版${label}模块（找到 ${found.length} 个）`);
    return resolve(found[0][0]);
  }
  return { find, count: factories.size };
}

function createAdapter({ bundle = latestBundle(), credential, transport, allowSend = false }) {
  const { token, key } = typeof credential === "string"
    ? parseCredential(credential)
    : credential;
  if (!token || !key || key.type !== "wechat_official") throw new Error("缺少原版微信加密凭据");
  if (!Number.isFinite(Number(key.expireAt)) || Number(key.expireAt) <= Date.now()) {
    throw new Error("微信加密 key 已过期，请重新从小程序提取凭据");
  }
  const store = new Map([
    ["token", token],
    ["crypto_key_info", JSON.stringify(key)]
  ]);
  const permitted = new Map([
    [CHECK_TOKEN, "GET"],
    [COURSES, "GET"]
  ]);
  if (allowSend) permitted.set(CHECKIN, "POST");
  if (!transport) transport = async ({ url, method, header, data }) => {
    const response = await fetch(url, {
      method,
      headers: header,
      body: method === "GET" ? undefined : JSON.stringify(data),
      redirect: "error",
      signal: AbortSignal.timeout(15000)
    });
    return { statusCode: response.status, data: await response.json() };
  };
  const wx = {
    getStorageSync: name => store.get(name) || "",
    setStorageSync: (name, value) => store.set(name, value),
    removeStorageSync: name => store.delete(name),
    getAppBaseInfo: () => ({ environment: "wx" }),
    getUserCryptoManager: () => ({
      getLatestUserKey() {
        throw new Error("本地无法刷新微信 key，请重新运行 CMD 提取");
      }
    }),
    showLoading() {},
    hideLoading() {},
    showToast() {},
    request(options) {
      const url = new URL(options.url);
      const method = (options.method || "GET").toUpperCase();
      const target = EXPECTED_BASE + url.pathname.slice("/icqust-admin".length);
      if (url.origin !== new URL(EXPECTED_BASE).origin ||
          !url.pathname.startsWith("/icqust-admin/") ||
          url.search || url.hash ||
          target !== options.url ||
          permitted.get(url.pathname.slice("/icqust-admin".length)) !== method) {
        throw new Error("原版模块请求了未获准的目标");
      }
      Promise.resolve()
        .then(() => transport({
          url: options.url,
          method,
          header: options.header,
          data: options.data
        }))
        .then(response => options.success?.(response),
          error => options.fail?.({ errMsg: String(error.message || error) }))
        .finally(() => options.complete?.());
    }
  };
  const modules = loadModules(bundle, wx);
  const api = modules.find("签到 API", ["checkInWithLocation:function", "myCourses:function"]);
  // Loading this module exercises the original request/crypto dependencies and validates the endpoint.
  const config = modules.find("服务地址", ["newBaseUrl:", "imgBaseUrl:"]);
  if (config.newBaseUrl !== EXPECTED_BASE) throw new Error("原版服务地址发生变化，请先核对");
  if (typeof api.myCourses !== "function" || typeof api.checkInWithLocation !== "function") {
    throw new Error("原版签到 API 不完整");
  }
  return {
    moduleCount: modules.count,
    courses: () => api.myCourses(),
    checkin(cnum, location) {
      if (!allowSend) throw new Error("未启用真实签到发送");
      if (!cnum || !location) throw new Error("缺少 cnum 或 location");
      return api.checkInWithLocation(cnum, location);
    }
  };
}

async function readCredential() {
  if (!process.stdin.isTTY) {
    let line = "";
    for await (const chunk of process.stdin) line += chunk;
    return line.trim();
  }
  process.stderr.write("粘贴 CMD 的 Credential（输入不会显示），回车继续：");
  const input = process.stdin;
  input.setRawMode(true);
  input.resume();
  try {
    return await new Promise((resolve, reject) => {
      let line = "";
      function onData(chunk) {
        for (const char of chunk.toString()) {
          if (char === "\r" || char === "\n") {
            input.off("data", onData);
            process.stderr.write("\n");
            return resolve(line.trim());
          }
          if (char === "\u0003") {
            input.off("data", onData);
            return reject(new Error("已取消"));
          }
          if (char === "\u007f" || char === "\b") line = line.slice(0, -1);
          else line += char;
        }
      }
      input.on("data", onData);
    });
  } finally {
    input.setRawMode(false);
    input.pause();
  }
}

async function main() {
  const [action = "courses", ...args] = process.argv.slice(2);
  const send = action === "checkin" && args.length === 3 && args[2] === "--send";
  if (!["courses", "checkin"].includes(action) ||
      (action === "checkin" && !send) ||
      (action === "courses" && args.length !== 0)) {
    throw new Error("用法：node miniapp_adapter.js courses 或 node miniapp_adapter.js checkin <cnum> <location> --send");
  }
  const credential = await readCredential();
  const adapter = createAdapter({ credential, allowSend: send });
  const result = action === "courses"
    ? await adapter.courses()
    : await adapter.checkin(args[0], args[1]);
  process.stdout.write(JSON.stringify(result, null, 2) + "\n");
}

if (require.main === module) {
  main().catch(error => {
    process.stderr.write(`失败：${error.message || "未知错误"}\n`);
    process.exitCode = 1;
  });
}

module.exports = { createAdapter, latestBundle, parseCredential };
