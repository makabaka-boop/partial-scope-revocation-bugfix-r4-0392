# 授权服务（授权码模式 + PKCE + 刷新令牌轮换/家族撤销）

Node.js 与 SQLite 实现的授权服务，供两个模拟客户端使用。

## 安全性质

1. **用户确认权限范围后签发短期授权码**（默认 10 分钟）。
2. **兑换三重绑定**：授权码必须同时匹配
   - 客户端（`client_id`），
   - 事先登记的**精确**回调地址（逐字符相等，查询串/结尾斜杠差异都拒绝），
   - PKCE：客户端发起时只提交随机验证值 `code_verifier` 的摘要 `code_challenge`，
     兑换时出示原值（S256）。
3. **授权码只能成功兑换一次**：写事务内以条件
   `UPDATE ... SET redeemed_at_ms=? WHERE ... AND redeemed_at_ms IS NULL` 原子消费，
   `changes===1` 才算成功。
4. **访问令牌有到期时间**（默认 1 小时）。
5. **刷新令牌每次使用都轮换**：旧令牌标记消费并指向新令牌，同属一个令牌家族。
6. **重放即家族撤销**：已用过的刷新令牌再次出现时，在同一事务内
   **撤销整个令牌家族**（`token_families.revoked_at_ms`），包括刚轮换出的最新令牌——
   家族内全部刷新令牌与访问令牌立即失效，撤销记录与原因持久化。
7. **可注入时钟**：所有到期判断只经过 `clock.now()`，测试用 `FakeClock` 推进时间。
8. **并发原子性**：
   - 实例内：异步互斥锁串行化写事务；
   - 实例间：`BEGIN IMMEDIATE` 取 RESERVED 写锁，冲突时让出事件循环并重试整个事务；
   - 一次性凭据的消费依赖条件 UPDATE，即使锁重试重放整个事务也不会双重发令牌。
9. **重启不复活**：全部状态落盘；重新打开同一数据库文件后，已兑换码、已轮换/已撤销
   令牌的状态原样恢复。
10. **只存摘要**：数据库保存授权码与令牌的 SHA-256，原始值仅出现在签发响应中；
    字符串比较使用常量时间比较。

## 目录结构

```
src/
  clock.js     Clock（系统时钟）/ FakeClock（测试可控时钟）
  crypto.js    随机串、SHA-256 摘要、PKCE S256、常量时间比较
  errors.js    AuthError（OAuth 风格错误码；commitAfterThrow 支持“撤销后报错仍提交”）
  db.js        SQLite 封装：互斥锁、BEGIN IMMEDIATE、SQLITE_BUSY 让出重试、建表
  server.js    AuthService：注册客户端 / 签发授权码 / 兑换 / 刷新轮换 / 家族撤销 / 校验
  http.js      零依赖 JSON HTTP 适配层（/authorize /token /introspect /revoke）
  client.js    MockOAuthClient：模拟客户端 SDK（生成 verifier、兑换、刷新）
  main.js      启动入口，登记两个模拟客户端
examples/
  demo.js      两个客户端经真实 HTTP 的端到端演示
test/          node:test 测试（26 个用例）
```

## 使用

```bash
npm install
npm test          # 26 个测试
npm run demo      # 端到端 HTTP 演示（含并发刷新与重启）
npm start         # 启动服务（默认 :3000，PORT / AUTH_DB 可覆盖）
```

存储引擎为 `node-sqlite3-wasm`（纯 WASM，无需原生编译）。封装层针对其两个与
better-sqlite3 不同的行为做了收口：绑定参数必须以单个数组传入；写事务期间其他
连接的任何语句（含 SELECT）会立即得到 `database is locked`，需让出事件循环重试。

## HTTP 接口（JSON）

| 路由 | 说明 |
| --- | --- |
| `POST /authorize` | 用户确认范围后签发授权码：`clientId, redirectUri, codeChallenge, codeChallengeMethod, scopes` |
| `POST /token` | `grantType: "authorization_code"`（`code, redirectUri, codeVerifier`）或 `"refresh_token"`（`refreshToken, scopes`） |
| `POST /introspect` | 校验访问令牌：`accessToken` |
| `POST /revoke` | 撤销家族：`familyId, reason` |

## 测试覆盖要点

- **两个客户端交叉兑换**：B 冒用签发给 A 的新码 → `授权码与客户端不匹配`，且码不被消费；
  跨客户端使用刷新令牌同样拒绝。
- **并发刷新**：
  - 单实例并发使用同一刷新令牌：恰一个成功，失败方触发家族撤销，获胜者的新令牌也立即失效；
  - 两个独立连接（多实例）并发：断言后到者经历真实写锁忙等待（`busyRetries>=1`），
    等待提交后读到“已消费”状态。
- **并发兑换授权码**：单实例与双连接两种场景下都只产生一组令牌。
- **范围越权**：签发阶段拒绝未开放范围；刷新时请求超集/不同范围返回 `invalid_scope`
  且不消费刷新令牌；两客户端范围互相隔离。
- **重放后的家族撤销**：轮换链 t0→t1→t2 后重放 t0，家族撤销；t2 的刷新/访问令牌、
  t1 的访问令牌全部失效；重启后撤销态依旧。
- **到期与持久化**：FakeClock 推进访问/刷新令牌 TTL；关闭后用同一文件重开，
  旧码旧令牌不复活；未撤销家族重启后仍可正常轮换。

## 部分范围撤销
POST /scope-grant 接受 clientId、scopes 和 granted 布尔值。撤销仅针对这个客户端，保留的范围继续可用。撤销后的旧授权码、旧访问及刷新凭据不应重新获得该范围；再次授权只对之后签发的授权码和凭据生效。全部范围失效的兑换不得签发令牌。原有到期、一次性消费和家族重放撤销仍生效。
