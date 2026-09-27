"use strict";

const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { createHash } = require("node:crypto");
const { spawnSync } = require("node:child_process");

const root = __dirname;
const output = path.join(root, "wx96_checkin_tool.html");
const packages = path.join(root, "local_wxapkg", "wxapkg_out");
const prefix = "wx96a1da8a627aa011_";
const beginMarker = "        // BEGIN GENERATED MINIAPP MODULES";
const endMarker = "        // END GENERATED MINIAPP MODULES";

function newestPackage() {
  const candidates = fs.readdirSync(packages, { withFileTypes: true })
    .filter(item => item.isDirectory() && item.name.startsWith(prefix))
    .map(item => ({
      version: Number(item.name.slice(prefix.length)),
      file: path.join(packages, item.name, "appservice.app.js")
    }))
    .filter(item => Number.isInteger(item.version) && fs.existsSync(item.file))
    .sort((a, b) => b.version - a.version);
  if (!candidates.length) throw new Error("没有找到已解包的小程序主包");
  return candidates[0];
}

function build() {
  const { version, file } = newestPackage();
  const source = fs.readFileSync(file, "utf8");
  const start = source.indexOf('define("');
  const end = source.lastIndexOf('require("app.js")');
  if (start < 0 || end <= start) throw new Error("无法识别小程序模块包装格式");
  const modules = new Map();
  vm.runInNewContext(source.slice(start, end), {
    define(id, factory) {
      if (modules.has(id)) throw new Error("解包模块重复：" + id);
      modules.set(id, factory);
    }
  }, { timeout: 5000, filename: path.basename(file) });
  if (modules.size < 10) throw new Error("提取的模块数异常");
  function unique(label, markers) {
    const matches = [...modules].filter(([, factory]) =>
      markers.every(marker => factory.toString().includes(marker)));
    if (matches.length !== 1) throw new Error(`无法唯一定位原版${label}模块`);
    return matches[0][0];
  }
  const api = unique("签到 API", ["checkInWithLocation:function", "myCourses:function"]);
  const request = unique("请求", ["postNew:function", "getNew:function"]);
  const crypto = unique("加密", ["getEncryptKey:function", "encryptRequest:function"]);
  const config = unique("服务地址", ["newBaseUrl:", "imgBaseUrl:"]);
  const selected = new Set();
  function include(id) {
    if (selected.has(id)) return;
    const factory = modules.get(id);
    if (!factory) throw new Error("模块依赖缺失：" + id);
    selected.add(id);
    for (const match of factory.toString().matchAll(/\brequire\(["']([^"']+)["']\)/g)) {
      const name = match[1];
      const dependency = name.startsWith(".")
        ? path.posix.normalize(path.posix.join(path.posix.dirname(id), name))
        : name;
      include(modules.has(dependency) ? dependency : dependency + ".js");
    }
  }
  include(api);
  for (const id of [request, crypto, config]) {
    if (!selected.has(id)) throw new Error("签到 API 未引用原版" + id);
  }
  const digest = createHash("sha256").update(source).digest("hex").slice(0, 16);
  const lines = [`        // package ${version}, sha256 ${digest}, ${selected.size} modules`];
  for (const [id, factory] of modules) {
    if (!selected.has(id)) continue;
    const text = factory.toString();
    if (text.toLowerCase().includes("</script")) {
      throw new Error("模块含有 HTML script 结束标记，不能直接嵌入");
    }
    lines.push(`        define(${JSON.stringify(id)}, ${text});`);
  }
  const html = fs.readFileSync(output, "utf8");
  const startAt = html.indexOf(beginMarker);
  const endAt = html.indexOf(endMarker);
  if (startAt < 0 || endAt <= startAt ||
      html.indexOf(beginMarker, startAt + 1) >= 0 ||
      html.indexOf(endMarker, endAt + 1) >= 0) {
    throw new Error("HTML 中的生成区域标记不唯一");
  }
  const newline = html.includes("\r\n") ? "\r\n" : "\n";
  const updated = html.slice(0, startAt + beginMarker.length) + newline +
    lines.join(newline) + newline + "        " +
    html.slice(endAt);
  return { html, updated, version, count: selected.size };
}

function main() {
  if (process.argv.includes("--unpack")) {
    if (process.argv.includes("--check")) throw new Error("--check 不能与 --unpack 同时使用");
    if (process.platform !== "win32") throw new Error("自动解包仅支持 Windows");
    const script = path.join(root, "local_wxapkg", "unpack_latest_wxapkg.ps1");
    const result = spawnSync("powershell.exe", [
      "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script
    ], { stdio: "inherit" });
    if (result.error || result.status !== 0) throw new Error("解包失败，HTML 未更新");
  }
  const { html, updated, version, count } = build();
  if (process.argv.includes("--check")) {
    if (html !== updated) throw new Error("HTML 内嵌模块与最新解包产物不一致");
    console.log(`已同步：版本 ${version}，${count} 个模块`);
    return;
  }
  if (html !== updated) fs.writeFileSync(output, updated);
  console.log(`已更新 HTML：版本 ${version}，${count} 个原版模块`);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}

module.exports = { build };
