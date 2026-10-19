# Banner Fingerprint

基于 Go 的 Banner 指纹识别系统。接收一批网络扫描原始数据（`ip` / `port` / `banner`），
识别协议、软件、版本与操作系统线索，输出统一 JSON；提供独立的 client 程序与
Docker Compose 一键启动能力。

识别规则与程序代码完全解耦：所有指纹都在 `rules/*.yaml` 中声明，新增规则无需改动
Go 代码，也无需重建镜像（容器内以只读卷挂载）。

---

## 1. 能力范围

| 协议 | 识别内容 | 示例 |
|---|---|---|
| SSH | OpenSSH / Dropbear，版本，发行版 | `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3` → OpenSSH 8.9p1 / Ubuntu |
| HTTP | nginx / Apache / Jetty / IIS / OpenResty / Caddy / Tomcat / lighttpd，版本，发行版 | `Server: nginx/1.24.0` → nginx 1.24.0 |
| MySQL | MySQL / MariaDB，握手包版本 | `\x00...\x0a8.0.32\x00` → MySQL 8.0.32 |
| Redis | 协议识别，`INFO` 场景可提取版本 | `-NOAUTH` / `+PONG` / `-ERR` → Redis |
| FTP | ProFTPD / vsftpd / Pure-FTPd / FileZilla / Microsoft FTP | `220 ProFTPD 1.3.7` → ProFTPD 1.3.7 |
| TLS | TLS 记录头字节签名 | `16 03 01 ...` → TLS |
| 其他 | 统一返回 `unknown`，服务不中断 | `QUIT` → unknown |

`unknown` 是**正常业务结果**，不是错误：单条数据无法识别不会影响同批其他数据，
也不会导致 HTTP 请求失败。

---

## 2. 架构

```text
                 读取本地 JSON                POST /fingerprint              规则匹配
┌──────────────┐  ───────────────>  ┌──────────────────┐  ───────────────>  ┌──────────────────┐
│ 本地输入文件  │                    │ client（独立程序）│                    │ server（Go, :8080）│
└──────────────┘                    └──────────────────┘                    └────────┬─────────┘
                                                                                    │ 只读加载
                                                                           ┌────────▼─────────┐
                                                                           │ rules/*.yaml      │
                                                                           │ （声明式指纹规则）  │
                                                                           └──────────────────┘
```

识别流水线：

```text
输入归一化 → 二进制签名预分类（TLS/MySQL）→ 规则匹配（正则命名捕获 + 端口先验）
          → 置信度打分 → 取最高分 → 输出（未命中则 unknown）
```

- **内容优先**：端口只参与置信度加权，不决定协议。因此 nginx 跑在 `8443`、IIS 跑在
  `8888`、SSH 跑在任意端口都能正确识别。
- **规则优先级**：`priority` 高者先匹配；最终结果取置信度最高者，同分时保留高优先级规则。
- **无状态、并发安全**：规则编译后只读，`Identify` 无共享可变状态。

---

## 3. 一键启动

```bash
docker compose up -d --build
```

启动后（宿主端口为 `7070`，映射到容器内 `8080`；避开本机其他项目常用的 8080）：

```bash
curl http://127.0.0.1:7070/health
curl -X POST http://127.0.0.1:7070/fingerprint \
  -H 'Content-Type: application/json' \
  -d '[{"ip":"1.2.3.4","port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3"}]'
```

运行客户端（一次性任务，位于 `client` profile）：

```bash
docker compose --profile client run --rm client
```

> 默认 `docker compose up` 只启动 server；client 是编排中的一次性任务，避免常驻容器
> 处于 Exited 状态造成误解。client 通过 `depends_on: service_healthy` 等待 server
> 真实就绪后再执行。

使用自己的输入文件：

```bash
docker compose --profile client run --rm \
  -v "$PWD/my-input.json:/data/input.json:ro" client
```

查看状态与日志：

```bash
docker compose ps
docker compose logs -f server
docker compose down
```

---

## 4. HTTP 接口

### 4.1 `POST /fingerprint`

请求体支持四种形态，均返回**裸数组**（与题面示例一致，顺序、长度与输入一致）：

```json
[
  { "ip": "1.2.3.4", "port": 22, "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" },
  { "ip": "1.2.3.7", "port": 3306, "banner_base64": "SgAAAAppOC4wLjMyAA==" }
]
```

| 形态 | 示例 |
|---|---|
| 裸数组（推荐） | `[{"ip":"...","port":22,"banner":"..."}]` |
| 包装对象 | `{"records":[...]}`（兼容 `items` / `data` / `inputs` / `results`） |
| 单条记录 | `{"ip":"...","port":22,"banner":"..."}` |
| 双层编码字符串 | `"[{\"ip\":\"...\"}]"` |

字段说明：

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ip` | string | 是 | 原样回显 |
| `port` | number/string | 否 | `22` 与 `"22"` 均可；非法值按 0 处理 |
| `banner` | string | 二选一 | 文本或字面量转义（`\x00`、`\r\n`） |
| `banner_base64` | string | 二选一 | 二进制 banner 推荐使用，避免转义损失 |

响应：

```json
[
  {
    "ip": "1.2.3.4",
    "port": 22,
    "protocol": "SSH",
    "product": "OpenSSH",
    "version": "8.9p1",
    "os_hint": "Ubuntu",
    "confidence": 0.95
  }
]
```

| 字段 | 说明 |
|---|---|
| `protocol` | `SSH` / `HTTP` / `TLS` / `MySQL` / `Redis` / `FTP` / `unknown` |
| `product` | 展示名；未知为空串（不是 `null`） |
| `version` | 未提取到版本时为空串 |
| `os_hint` | 仅当 banner 有明确线索时填写 |
| `confidence` | `0 ~ 1`；`unknown` 为 `0` |

响应头（不改变 body 契约）：

- `X-Total-Count`：本批总数
- `X-Identified-Count`：已识别数量
- `X-Elapsed-Ms`：服务端处理耗时
- `X-Request-ID`：请求追踪 ID（也可由客户端传入）

错误契约（仅结构性错误才返回非 200，单条识别失败永不报错）：

```json
{
  "error": {
    "code": "invalid_json",
    "message": "invalid JSON array: ...",
    "request_id": "9f2c..."
  }
}
```

| 状态码 | 场景 |
|---|---|
| 400 | 请求体不是合法 JSON / 不支持的顶层结构 |
| 405 | 方法错误（带 `Allow` 头） |
| 413 | 请求体超过 8 MiB |
| 500 | 内部异常（panic 已恢复，仍返回结构化错误） |

### 4.2 `GET /health`

```json
{
  "status": "ok",
  "version": "1.0.0",
  "uptime_s": 11.47,
  "rules": { "files": 6, "loaded": 32, "source": "/app/rules" }
}
```

Docker HEALTHCHECK 通过二进制内置的 `-healthcheck` 子命令调用该接口，
而不是简单检查进程存活。

---

## 5. 客户端

```bash
# 本地二进制
go run ./cmd/client -in ./testdata/input.json -server http://127.0.0.1:7070 -out ./results.json

# 容器
docker compose --profile client run --rm client
```

| 参数 | 环境变量 | 默认值 | 说明 |
|---|---|---|---|
| `-in` | - | `testdata/input.json` | 输入文件 |
| `-server` | `FINGERPRINT_SERVER` | `http://127.0.0.1:7070` | 服务地址 |
| `-out` | - | 空 | 可选，结果写入 JSON |
| `-timeout` | - | `30s` | 请求超时 |

退出码：`0` 成功，`2` 服务不可达/非 200，`3` 输入文件不可读或非法 JSON。

输出示例：

```text
IP        PORT   PROTOCOL  PRODUCT        VERSION  OS_HINT  CONFIDENCE
1.2.3.4   22     SSH       OpenSSH        8.9p1    Ubuntu   0.95
1.2.3.5   80     HTTP      nginx          1.24.0   -        0.90
...
1.2.3.23  12345  unknown   -              -        -        0.00

total=20 identified=19 unknown=1
```

---

## 6. 规则系统（与代码解耦）

规则文件位于 `rules/`，启动时由 `RULES_DIR` 指定目录加载。容器中以
`./rules:/app/rules:ro` 只读挂载：修改规则后重启容器即可生效，无需重新构建镜像。

### 6.1 规则结构

```yaml
version: 1
rules:
  - id: ssh-openssh              # 唯一标识，必填
    priority: 100                # 匹配优先级（高者先匹配）
    protocol: SSH                # 协议名，不能为 unknown
    product: OpenSSH             # 固定产品名
    ports: [22, 2222]            # 端口先验，仅用于置信度加分
    match:
      type: regex                # regex | prefix | contains | bytes_hex
      pattern: '(?im)^SSH-(?P<protover>[0-9.]+)-OpenSSH_(?P<version>[0-9][0-9A-Za-z._\-]*)'
    os_hint:
      - { pattern: '(?i)Ubuntu', value: Ubuntu }
    base_confidence: 0.90        # 基础置信度
    port_bonus: 0.05             # 端口命中时的加分（0 ~ 0.2）
```

约定：

- 命名捕获组 `version` → 版本号；命名捕获组 `product` → 动态产品名（`product` 为空时生效）。
- `bytes_hex` 对原始字节做**前缀**匹配，用于 TLS（`1603`）、自定义二进制协议。
- 规则使用 Go RE2 正则，不支持反向引用与环视，天然避免灾难性回溯。
- 启动时严格校验：字段拼错、正则非法、`base_confidence` 越界都会**直接启动失败**，
  避免"规则看似生效、实际被静默忽略"。

### 6.2 新增一条规则

例如识别 `Server: H2O/2.2.6`：

```yaml
  - id: http-h2o
    priority: 90
    protocol: HTTP
    product: H2O
    match:
      type: regex
      pattern: '(?i)\bServer:\s*H2O/(?P<version>[0-9][^\s;()\r\n,]*)'
    base_confidence: 0.85
```

放入 `rules/http.yaml` 后重启 server 即可，Go 代码零改动。

---

## 7. 生产化设计

### 7.1 网络收敛

- `backend` 网络设置 `internal: true`，client 只能访问 server，无法访问外网。
- server 同时接入 `edge` 网络并向宿主发布端口，且绑定 `127.0.0.1`，局域网不可见。
- 容器间访问唯一路径为服务名 `http://server:8080`，无 `host.docker.internal`、
  无硬编码容器 IP、无额外开放端口。

### 7.2 真实健康检测

- server 镜像基于 `scratch`，没有 `curl/wget/sh`；
- 健康检查复用二进制自身的 `-healthcheck` 子命令，实际请求 `/health` 并校验
  `status == "ok"`；
- client 使用 `depends_on: condition: service_healthy`，确保 server 真正就绪
  （而非仅进程启动）后才执行。

### 7.3 构建与打包

- 多阶段构建：`golang:1.26-alpine` 编译 → `scratch` 运行；
- `CGO_ENABLED=0` + 纯静态二进制，`-trimpath` 去除构建机路径，`-s -w` 去除符号表；
- 依赖已 `go mod vendor`，构建阶段不访问 module proxy，构建可离线复现；
- 最终镜像仅包含二进制与规则文件，无 shell、无包管理器、无 C 库；
- `.dockerignore` 排除 `.git`、测试文件等无关内容，缩小构建上下文。

### 7.4 运行权限收紧

server 与 client 均启用：

```yaml
read_only: true            # 根文件系统只读
user: "65532:65532"        # 非 root
cap_drop: [ALL]            # 丢弃全部 Linux capabilities
security_opt:
  - no-new-privileges:true # 禁止提权
tmpfs: /tmp                # 唯一可写目录，且 noexec/nosuid
pids_limit: 256
mem_limit: 256m
cpus: 1.0
```

### 7.5 可观测性与健壮性

- 结构化 JSON 日志（`slog`），包含 `request_id`、状态码、耗时、字节数；
- panic 恢复中间件，异常不会导致进程退出；
- 请求体 8 MiB 上限、banner 64 KiB 匹配上限；
- HTTP 读写超时、空闲超时、Header 大小限制；
- 收到 SIGTERM 后 10s 优雅退出，配合 `stop_grace_period: 15s`。

---

## 8. 目录结构

```text
.
├── cmd/
│   ├── server/main.go          # HTTP 服务入口 + -healthcheck 子命令
│   └── client/main.go          # 独立客户端
├── internal/
│   ├── api/                    # 路由、请求解析、错误契约、中间件
│   ├── engine/                 # 归一化、规则匹配、置信度打分
│   ├── model/                  # client/server 共用数据结构
│   └── rules/                  # YAML 规则加载、编译与校验
├── rules/                      # 声明式指纹规则（与代码解耦）
│   ├── ssh.yaml
│   ├── http.yaml
│   ├── mysql.yaml
│   ├── redis.yaml
│   ├── ftp.yaml
│   └── tls.yaml
├── testdata/input.json         # 自测数据（20 条）
├── Dockerfile                  # 多 target：server / client
├── docker-compose.yml
├── Makefile
└── vendor/                     # 依赖固化，离线可构建
```

---

## 9. 本地开发与测试

```bash
# 单元测试（包含 20 条样例的 golden 断言与异常输入测试）
go test ./...

# 构建
go build -o bin/server ./cmd/server
go build -o bin/client ./cmd/client

# 本地运行
./bin/server -addr :7070 -rules ./rules
./bin/client -in ./testdata/input.json -server http://127.0.0.1:7070

# Compose 全链路
docker compose up -d --build
docker compose --profile client run --rm client
```

`testdata/input.json` 覆盖：

- SSH（含 `SSH-1.99`）、HTTP（nginx / Apache / Jetty / IIS，含非标准端口）、
  MySQL（二进制握手包）、Redis（`-ERR` / `+PONG` / `-NOAUTH`）、
  FTP（ProFTPD / vsftpd / 无版本 Pure-FTPd）、TLS 记录头、无法识别的文本；
- 额外单测覆盖：空 banner、超长 banner、非法 base64、负端口、超范围端口、
  双层 JSON 编码、非法 `\xNN` 转义、包装对象/单条记录等形态。

---

## 10. 边界与约定

- **TLS 与 HTTP 的区分**：纯 TLS 记录头（`16 03 ...`）输出 `protocol: "TLS"`；
  若 banner 本身是明文 HTTP 响应，即使端口为 443 也输出 `HTTP`。
- **不猜测**：没有足够证据时宁可返回 `unknown`，也不输出低可信度的产品名。
- **置信度语义**：签名强度（协议+产品+版本）> 仅协议 > 仅端口；端口仅在规则
  显式声明时加分。该值是启发式排序依据，不是概率校准结果。
- **无认证**：按题目要求仅提供两个接口。若部署到不可信网络，应在前面增加
  网关鉴权/速率限制；当前 compose 已将端口绑定回环地址作为最低限度保护。
- **规则与代码的一致性**：规则加载失败时进程直接退出，容器不会进入"半可用"状态。

---

## 11. 配置项

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `HTTP_ADDR` | `:8080` | server 监听地址（容器内） |
| `RULES_DIR` | `./rules` | 规则目录（容器内为 `/app/rules`） |
| `HEALTHCHECK_URL` | `http://127.0.0.1:8080/health` | 健康检查地址（容器内） |
| `FINGERPRINT_SERVER` | `http://127.0.0.1:7070` | client 默认服务地址（宿主侧） |
| `GOMAXPROCS` | 继承 | 容器内限制为 2 |

命令行参数优先级高于环境变量。
