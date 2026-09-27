# 原版小程序请求适配器

先运行 `双击运行_获取token.cmd`，从小程序提取当前的 Credential。适配器直接加载
`local_wxapkg/wxapkg_out` 下版本号最高的 `appservice.app.js`，调用其中的
`myCourses` 和 `checkInWithLocation`，由原版代码完成取签名密钥、加密、签名、
发送、响应解密与重试。HTML 通过 `miniapp_web.js` 接入此适配器，不再重建签名。

本机需安装 Node.js。打开此目录中的终端：

```text
node miniapp_web.js
node miniapp_adapter.js courses
node miniapp_adapter.js checkin "class_num-teacherId-123456" "纬度:29.00经度:106.00" --send
```

第一条命令启动本地页面，浏览器打开终端显示的 `127.0.0.1` 地址。不要直接打开
HTML 文件；浏览器只请求本机服务，服务再调用原版模块发送请求。

运行后再粘贴 CMD 输出的整条 Credential 并回车。终端交互输入不回显，也不会保存
Credential。管道标准输入也可用于本地自动化，但不要将凭据写入命令参数、
命令历史或版本库。`courses` 只发送 `checkToken` 与课程 GET；签到仅在明确传入
`--send` 后才开放对应的 POST。其他 URL 和方法一律拒绝。

微信加密 key 过期时应重新打开小程序并运行 CMD 获取凭据；本地无法调用微信接口
刷新 key。新版解包如改变模块包装、服务地址或 API 形状，适配器会报错，需先核对。
离线验证：`node --test miniapp_adapter.test.js`。测试只使用虚构凭据和模拟网络，
不访问实际服务。
