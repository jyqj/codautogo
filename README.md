# codex Go 版部署与运行说明

## 1. 项目说明

这是一个基于 Go 的：

- OpenAI 账号注册
- OAuth 登录
- workspace / org token 录入
- 最终投递到 **CLIProxyAPI / CPA**

当前项目已经：

- **移除旧的 codex-server 投递链路**
- 默认投递目标为 `clean.base_url + clean.token`
- 邮箱链路固定为 **`tabmail -> cfmail`**
- 支持配置 **多组 cfmail**
- 双池 / 维护模式会把邮箱 token 一起带入队列，保证 OAuth 阶段还能走 fallback

---

## 2. 配置文件

项目运行依赖：

- `config.json`
- `.env`（可选，但推荐）

如果你不想直接改现有配置，可以先复制模板：

```bash
cp config.example.json config.json
touch .env
```

---

## 3. 关键配置

### 3.1 投递目标（必配）

`config.json`：

```json
"clean": {
  "base_url": "http://127.0.0.1:8317",
  "token": "YOUR_CPA_PASSWORD"
}
```

说明：

- `clean.base_url`：CLIProxyAPI / CPA 地址
- `clean.token`：CLIProxyAPI / CPA 管理 token

> 旧的 `SERVER_BASE` / `ADMIN_AUTH` 已废弃，不再使用。

### 3.2 邮箱链路

`config.json`：

```json
"cf_mail_configs": [
  {
    "name": "cfmail-1",
    "worker_domain": "your-worker-domain-1.example.com",
    "email_domain": "your-mail-domain-1.example.com",
    "admin_password": "replace-me-1"
  },
  {
    "name": "cfmail-2",
    "worker_domain": "your-worker-domain-2.example.com",
    "email_domain": "your-mail-domain-2.example.com",
    "admin_password": "replace-me-2"
  }
]
```

行为固定为：

1. 先尝试 TabMail
2. TabMail 失败后，按 `cf_mail_configs` 顺序依次 fallback

> 旧的单组配置 `cf_worker_domain / cf_email_domain / cf_admin_password` 仍兼容，但推荐迁移到 `cf_mail_configs`。

### 3.3 TabMail 配置

`.env`：

```bash
TABMAIL_URL=http://your-tabmail-host:3000
TABMAIL_ADMIN_KEY=xxxx
TABMAIL_TENANT_ID=00000000-0000-0000-0000-000000000001
TABMAIL_ZONE_ID=xxxx
```

### 3.4 是否本地落 token

`config.json`：

```json
"output": {
  "save_local": false
}
```

如果设为 `false`，则只投递 CPA，不落本地 `ak.txt/rk.txt`。

---

## 4. 代理文件（可选）

如果你使用文件代理模式：

```bash
mkdir -p runtime logs
cp /你的代理文件路径/proxies.txt runtime/proxies.txt
```

然后保证：

```json
"proxy_mode": "file",
"proxy_file": "/app/runtime/proxies.txt"
```

---

## 5. Docker 部署

### 5.1 构建镜像

```bash
docker compose build
```

### 5.2 启动

```bash
mkdir -p logs runtime
docker compose up -d
```

### 5.3 查看状态

```bash
docker compose ps
docker compose logs -f codex
tail -f logs/error.log
```

---

## 6. 常用运行方式

### 6.1 默认批量运行

```bash
docker compose up -d
```

### 6.2 单邮箱处理

```bash
docker compose run --rm codex \
  --email your_email@example.com \
  --password your_password \
  --skip-register
```

### 6.3 团队区间批量

```bash
docker compose run --rm codex \
  --team-range 10031-10035 \
  --per-team 7 \
  --qiuming-start 1 \
  --proxy-file /app/runtime/proxies.txt
```

### 6.4 双池模式

```bash
docker compose run --rm codex \
  --dual-pool \
  --reg-workers 2 \
  --oauth-workers 2 \
  --oauth-delay 3 \
  --proxy-file /app/runtime/proxies.txt
```

### 6.5 持续维护模式

```bash
docker compose run --rm codex \
  --maintain \
  --reg-workers 2 \
  --oauth-workers 2 \
  --min-candidates 50 \
  --loop-interval 60
```

---

## 7. 常用参数

- `--mail-provider`：已废弃，当前固定链路为 `tabmail -> cfmail`
- `--dual-pool`：注册池和 OAuth 池异步运行
- `--maintain`：持续补号，OAuth 池受 CPA candidates 库存控制
- `--proxy-mode direct|file`
- `--proxy-file /app/runtime/proxies.txt`

---

## 8. 目录说明

```text
.
├── Dockerfile
├── docker-compose.yml
├── config.example.json
├── config.json
├── .env
├── logs/
├── runtime/
├── cmd/
└── internal/
```

---

## 9. 说明

- Docker 镜像**不会打包** `config.json`、`.env`、运行数据和日志文件
- 容器内 `stderr` 会追加到 `logs/error.log`
- 容器内 `stdout` 走 Docker 日志
- 如果启动时看到 `📌 投递目标: 仅本地保存`，说明你还没配 `clean.base_url/token`
