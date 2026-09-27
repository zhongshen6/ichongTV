# 原版小程序请求适配器

`wx96_checkin_tool.html` 可直接用浏览器打开。文件内的
`BEGIN GENERATED MINIAPP MODULES` 与 `END GENERATED MINIAPP MODULES` 之间是
自动生成区域；其余代码是浏览器内的微信接口适配层和页面逻辑。适配层调用原版
`myCourses`、`checkInWithLocation` 及其依赖，原版代码完成加密、签名、发送、
响应处理与重试。不要手工修改生成区域。

小程序重新解包后，在项目目录运行：

```text
node update_miniapp_bundle.js --unpack
node update_miniapp_bundle.js
node update_miniapp_bundle.js --check
node --test update_miniapp_bundle.test.js
```

第一条命令可选：它先运行现有的 `local_wxapkg/unpack_latest_wxapkg.ps1`，
从电脑微信缓存中解包最新版，再更新 HTML；该解包脚本默认会替换同版本的现有
输出目录。本机需已有对应解包工具；`local_wxapkg` 不在 Git 仓库中。已经解包时
只需运行第二条命令，`--check` 只读校验。

脚本选取 `local_wxapkg/wxapkg_out` 中版本号最高的
`wx96a1da8a627aa011_*/appservice.app.js`，机械提取签到 API 及递归依赖的
原版模块，更新 HTML 中的生成区域。无法唯一定位模块或缺少依赖时会报错，
不会生成猜测的签名实现。测试只使用虚构凭据和模拟网络。

运行 `双击运行_获取token.cmd` 获取当前 Credential，再把 HTML 直接拖入浏览器
并粘贴 Credential。浏览器直接向目标接口发送请求，不需要 Node 服务。微信加密
key 过期时应重新打开小程序并重新提取；网页无法调用微信接口刷新 key。浏览器
仍可能受到 CORS 或网络环境限制，请勿把 Credential 分享给他人。
