'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { AuthService } = require('./server');
const { Clock } = require('./clock');
const { createJsonServer } = require('./http');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = process.env.AUTH_DB || path.join(DATA_DIR, 'auth.db');
const PORT = Number(process.env.PORT || 3000);

/**
 * 两个事先登记的模拟客户端。
 * 回调地址必须精确匹配（查询串、结尾斜杠差异都会被拒）。
 */
const REGISTERED_CLIENTS = [
  {
    clientId: 'client-webapp',
    name: '示例 Web 应用',
    redirectUris: ['http://127.0.0.1:5173/callback'],
    scopes: ['read:profile', 'read:documents'],
  },
  {
    clientId: 'client-mobile',
    name: '示例移动应用',
    redirectUris: ['com.example.mobile://oauth/callback'],
    scopes: ['read:profile', 'write:documents'],
  },
];

async function main() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const auth = new AuthService({ db: DB_PATH, clock: new Clock() });
  for (const c of REGISTERED_CLIENTS) await auth.registerClient(c);

  const server = createJsonServer(auth);
  server.listen(PORT, () => {
    console.log(`授权服务已启动: http://127.0.0.1:${PORT}`);
    console.log(`数据库: ${DB_PATH}`);
    console.log('已登记客户端:');
    for (const c of REGISTERED_CLIENTS) {
      console.log(`  - ${c.clientId}  回调=${c.redirectUris.join(', ')}  范围=${c.scopes.join(' ')}`);
    }
    console.log('\n运行端到端演示: npm run demo');
  });

  const shutdown = () => {
    server.close(() => {
      auth.close();
      process.exit(0);
    });
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

if (require.main === module) {
  main().catch((e) => {
    console.error('启动失败:', e);
    process.exit(1);
  });
}

module.exports = { REGISTERED_CLIENTS, DB_PATH, DATA_DIR, PORT };
