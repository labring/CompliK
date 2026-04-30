# sealos-complik-admin

[English](#english) | [中文](#zh-cn)

<a id="english"></a>

## English

Administrative backend service for managing project configuration and user compliance records. The service is built with Gin and GORM, stores data in MySQL, and runs automatic schema migration on startup.

### Features

- Health check endpoint for service monitoring
- CRUD APIs for project configs, commitments, bans, and unban operations
- Split violation APIs for CompliK and Procscan event storage and querying
- Ban screenshot upload and admin-side proxy preview
- Markdown-ready ban reason storage and rendering support
- Namespace status endpoints for bans and violations
- YAML-based configuration, OSS integration, and file logging
- Docker image for containerized deployment

### Tech Stack

- Go `1.26.1`
- Gin
- GORM
- MySQL
- Docker

### Project Structure

```text
.
|-- cmd/                     # Application entrypoint
|-- configs/                 # YAML configuration files
|-- internal/
|   |-- infra/               # Config, database, migration
|   |-- modules/             # Domain modules
|   |   |-- ban/
|   |   |-- complikviolation/
|   |   |-- commitment/
|   |   |-- procscanviolation/
|   |   |-- projectconfig/
|   |   |-- unban/
|   `-- router/              # HTTP route registration
|-- test/postman.json        # Postman collection
|-- Dockerfile
`-- start.sh                 # Local startup helper
```

### Modules

- `projectconfig`: store and manage project-level configuration records
- `commitment`: manage uploaded commitment files and download streaming
- `complikviolation`: store and query CompliK content violation events
- `procscanviolation`: store and query Procscan process violation events
- `ban`: manage ban history, markdown reasons, screenshot upload, and screenshot proxy preview
- `unban`: track unban actions

### Requirements

- Go `1.26.1` or later
- MySQL instance reachable by the application
- An existing database named `sealos-complik-admin` or a custom database configured in the YAML file

Example database creation:

```sql
CREATE DATABASE `sealos-complik-admin`
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;
```

### Configuration

The application resolves the config file in this order:

1. `CONFIG_FILE`
2. `/config/config.yaml`
3. `configs/config.yaml`

```yaml
port: 8080

database:
  host: localhost
  port: 3306
  username: root
  password: sealos123
  name: sealos-complik-admin

oss:
  endpoint: http://minio.objectstorage-system.svc.cluster.local
  bucket: sealos-complik-admin
  access_key_id: minioadmin
  access_key_secret: minioadmin
  public_base_url: https://files.example.com
  object_prefix: complik-admin
```

Notes:

- Tables are auto-migrated at startup.
- The application does not create the MySQL database itself.
- `oss.endpoint` uses an S3-compatible endpoint such as MinIO.
- `oss.object_prefix` is used for commitment and ban screenshot object keys.
- Ban screenshots support admin-side proxy preview through `/api/bans/screenshots`.
- CompliK and Procscan violation list endpoints return illegal events by default. `include_all=true` returns the full event stream.

### Run Locally

1. Update `configs/config.yaml` for your environment.
2. Make sure MySQL is running and the target database already exists.
3. Start the service with one of the following commands:

```bash
go run ./cmd
```

```bash
./start.sh
```

`start.sh` checks port `8080`, stops any process already listening on that port, and then starts the app.

### Run with Docker

Build the image:

```bash
docker build -t sealos-complik-admin .
```

Run the container:

```bash
docker run --rm -p 8080:8080 sealos-complik-admin
```

If MySQL is not running inside the same network as the container, update `configs/config.yaml` with a reachable database host before building or running the image.

### API Overview

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/health` | Health check |
| `POST` | `/api/configs` | Create project config |
| `GET` | `/api/configs` | List project configs |
| `GET` | `/api/configs/type/:config_type` | List project configs by type |
| `GET` | `/api/configs/:config_name` | Get project config by name |
| `PUT` | `/api/configs/:config_name` | Update project config |
| `DELETE` | `/api/configs/:config_name` | Delete project config |
| `POST` | `/api/commitments` | Create commitment |
| `POST` | `/api/commitments/upload` | Upload commitment file |
| `GET` | `/api/commitments` | List commitments |
| `GET` | `/api/commitments/:namespace` | Get commitment by namespace |
| `GET` | `/api/commitments/:namespace/download` | Download commitment file |
| `PUT` | `/api/commitments/:namespace` | Update commitment |
| `DELETE` | `/api/commitments/:namespace` | Delete commitment |
| `POST` | `/api/complik-violations` | Create CompliK violation event |
| `GET` | `/api/complik-violations` | List CompliK illegal events, `include_all=true` returns all events |
| `GET` | `/api/complik-violations/:namespace` | Get CompliK events by namespace |
| `DELETE` | `/api/complik-violations/id/:id` | Delete CompliK event by id |
| `DELETE` | `/api/complik-violations/:namespace` | Delete CompliK events by namespace |
| `GET` | `/api/namespaces/:namespace/complik-violations-status` | Check whether a namespace has CompliK illegal events |
| `POST` | `/api/procscan-violations` | Create Procscan violation event |
| `GET` | `/api/procscan-violations` | List Procscan illegal events, `include_all=true` returns all events |
| `GET` | `/api/procscan-violations/:namespace` | Get Procscan events by namespace |
| `DELETE` | `/api/procscan-violations/id/:id` | Delete Procscan event by id |
| `DELETE` | `/api/procscan-violations/:namespace` | Delete Procscan events by namespace |
| `GET` | `/api/namespaces/:namespace/procscan-violations-status` | Check whether a namespace has Procscan illegal events |
| `POST` | `/api/bans` | Create ban record |
| `POST` | `/api/bans/upload` | Create ban record with screenshot upload |
| `GET` | `/api/bans/screenshots` | Proxy preview for ban screenshots |
| `GET` | `/api/bans` | List ban records |
| `GET` | `/api/bans/:namespace` | Get bans by namespace |
| `DELETE` | `/api/bans/id/:id` | Delete a ban record by id |
| `GET` | `/api/namespaces/:namespace/ban-status` | Check whether a namespace is banned |
| `POST` | `/api/unbans` | Create unban record |
| `GET` | `/api/unbans` | List unban records |
| `GET` | `/api/unbans/:namespace` | Get unban records by namespace |
| `DELETE` | `/api/unbans/id/:id` | Delete an unban record by id |

### Example Requests

Health check:

```bash
curl http://localhost:8080/health
```

Create a project config:

```bash
curl -X POST http://localhost:8080/api/configs \
  -H "Content-Type: application/json" \
  -d '{
    "config_name": "project-config-demo",
    "config_type": "json",
    "config_value": {"enabled": true, "threshold": 3},
    "description": "Demo config"
  }'
```

Create a commitment:

```bash
curl -X POST http://localhost:8080/api/commitments \
  -H "Content-Type: application/json" \
  -d '{
    "namespace": "ns-demo",
    "file_name": "commitment.pdf",
    "file_url": "https://oss.example.com/commitments/commitment.pdf"
  }'
```

Upload a ban with screenshots:

```bash
curl -X POST http://localhost:8080/api/bans/upload \
  -F "namespace=ns-demo" \
  -F "reason=## Ban Reason\n- screenshot attached" \
  -F "ban_start_time=2026-04-21T14:30:00Z" \
  -F "operator_name=alice" \
  -F "screenshots=@/tmp/sample.png"
```

List all CompliK events:

```bash
curl "http://localhost:8080/api/complik-violations?include_all=true"
```

### API Collection

Import `test/postman.json` into Postman to quickly try the available APIs.

---

<a id="zh-cn"></a>

## 中文

这是一个用于管理项目配置和用户合规记录的管理后台服务，基于 Gin 和 GORM 构建，数据存储在 MySQL 中，并在启动时自动执行表结构迁移。

### 功能特性

- 提供健康检查接口，便于服务监控
- 提供项目配置、承诺书、封禁、解封的 CRUD 接口
- 提供 CompliK 与 Procscan 的分离违规事件接口
- 支持封禁截图上传与 admin 代理预览
- 支持封禁原因以 Markdown 形式存储与展示
- 提供 namespace 维度的封禁状态与违规状态查询接口
- 使用 YAML 配置文件、OSS 和本地日志目录
- 提供 Docker 镜像构建能力，便于容器化部署

### 技术栈

- Go `1.26.1`
- Gin
- GORM
- MySQL
- Docker

### 项目结构

```text
.
|-- cmd/                     # 应用入口
|-- configs/                 # YAML 配置文件
|-- internal/
|   |-- infra/               # 配置、日志、数据库、迁移
|   |-- modules/             # 业务模块
|   |   |-- ban/
|   |   |-- complikviolation/
|   |   |-- commitment/
|   |   |-- procscanviolation/
|   |   |-- projectconfig/
|   |   |-- unban/
|   |   `-- violation/
|   `-- router/              # HTTP 路由注册
|-- test/postman.json        # Postman 集合
|-- Dockerfile
`-- start.sh                 # 本地启动辅助脚本
```

### 模块说明

- `projectconfig`：管理项目级配置项
- `commitment`：管理承诺书文件上传和下载流
- `complikviolation`：记录和查询 CompliK 内容违规事件
- `procscanviolation`：记录和查询 Procscan 进程违规事件
- `violation`：保留兼容用的通用违规接口
- `ban`：管理封禁历史、Markdown 描述、截图上传和截图代理预览
- `unban`：记录解封操作

### 运行要求

- Go `1.26.1` 或更高版本
- 可被服务访问的 MySQL 实例
- 已存在的 `sealos-complik-admin` 数据库，或在配置文件中指定其他数据库名

示例建库语句：

```sql
CREATE DATABASE `sealos-complik-admin`
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;
```

### 配置说明

应用按以下顺序解析配置文件：

1. `CONFIG_FILE`
2. `/config/config.yaml`
3. `configs/config.yaml`

```yaml
port: 8080

database:
  host: localhost
  port: 3306
  username: root
  password: sealos123
  name: sealos-complik-admin

oss:
  endpoint: http://minio.objectstorage-system.svc.cluster.local
  bucket: sealos-complik-admin
  access_key_id: minioadmin
  access_key_secret: minioadmin
  public_base_url: https://files.example.com
  object_prefix: complik-admin
```

说明：

- 服务启动时会自动执行数据表迁移。
- 应用不会自动创建 MySQL 数据库本身。
- `oss.endpoint` 使用兼容 S3 的对象存储地址。
- `oss.object_prefix` 用于承诺书和封禁截图对象路径前缀。
- 封禁截图支持通过 `/api/bans/screenshots` 走 admin 代理预览。
- CompliK 和 Procscan 违规列表接口默认返回违规事件，`include_all=true` 返回全量事件。

### 本地运行

1. 根据你的环境修改 `configs/config.yaml`。
2. 确认 MySQL 已启动，且目标数据库已经存在。
3. 使用以下任一命令启动服务：

```bash
go run ./cmd
```

```bash
./start.sh
```

`start.sh` 会先检查 `8080` 端口，占用时会停止对应进程，然后再启动应用。

### Docker 运行

构建镜像：

```bash
docker build -t sealos-complik-admin .
```

运行容器：

```bash
docker run --rm -p 8080:8080 sealos-complik-admin
```

如果 MySQL 不在容器同一网络内，请在构建或运行前先把 `configs/config.yaml` 中的数据库地址改成容器可访问的地址。

### 接口概览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `GET` | `/health` | 健康检查 |
| `POST` | `/api/configs` | 创建项目配置 |
| `GET` | `/api/configs` | 查询项目配置列表 |
| `GET` | `/api/configs/type/:config_type` | 按配置类型查询项目配置 |
| `GET` | `/api/configs/:config_name` | 按名称查询项目配置 |
| `PUT` | `/api/configs/:config_name` | 更新项目配置 |
| `DELETE` | `/api/configs/:config_name` | 删除项目配置 |
| `POST` | `/api/commitments` | 创建承诺记录 |
| `POST` | `/api/commitments/upload` | 上传承诺书文件 |
| `GET` | `/api/commitments` | 查询承诺记录列表 |
| `GET` | `/api/commitments/:namespace` | 按 namespace 查询承诺记录 |
| `GET` | `/api/commitments/:namespace/download` | 下载承诺书文件 |
| `PUT` | `/api/commitments/:namespace` | 更新承诺记录 |
| `DELETE` | `/api/commitments/:namespace` | 删除承诺记录 |
| `POST` | `/api/complik-violations` | 创建 CompliK 违规事件 |
| `GET` | `/api/complik-violations` | 查询 CompliK 违规事件列表，`include_all=true` 返回全量事件 |
| `GET` | `/api/complik-violations/:namespace` | 按 namespace 查询 CompliK 事件 |
| `DELETE` | `/api/complik-violations/id/:id` | 按 id 删除 CompliK 事件 |
| `DELETE` | `/api/complik-violations/:namespace` | 按 namespace 删除 CompliK 事件 |
| `GET` | `/api/namespaces/:namespace/complik-violations-status` | 查询 namespace 是否存在 CompliK 违规事件 |
| `POST` | `/api/procscan-violations` | 创建 Procscan 违规事件 |
| `GET` | `/api/procscan-violations` | 查询 Procscan 违规事件列表，`include_all=true` 返回全量事件 |
| `GET` | `/api/procscan-violations/:namespace` | 按 namespace 查询 Procscan 事件 |
| `DELETE` | `/api/procscan-violations/id/:id` | 按 id 删除 Procscan 事件 |
| `DELETE` | `/api/procscan-violations/:namespace` | 按 namespace 删除 Procscan 事件 |
| `GET` | `/api/namespaces/:namespace/procscan-violations-status` | 查询 namespace 是否存在 Procscan 违规事件 |
| `POST` | `/api/bans` | 创建封禁记录 |
| `POST` | `/api/bans/upload` | 上传截图并创建封禁记录 |
| `GET` | `/api/bans/screenshots` | admin 代理预览封禁截图 |
| `GET` | `/api/bans` | 查询封禁记录列表 |
| `GET` | `/api/bans/:namespace` | 按 namespace 查询封禁记录 |
| `DELETE` | `/api/bans/id/:id` | 按 id 删除封禁记录 |
| `GET` | `/api/namespaces/:namespace/ban-status` | 查询 namespace 是否处于封禁状态 |
| `POST` | `/api/unbans` | 创建解封记录 |
| `GET` | `/api/unbans` | 查询解封记录列表 |
| `GET` | `/api/unbans/:namespace` | 按 namespace 查询解封记录 |
| `DELETE` | `/api/unbans/id/:id` | 按 id 删除解封记录 |

### 请求示例

健康检查：

```bash
curl http://localhost:8080/health
```

创建项目配置：

```bash
curl -X POST http://localhost:8080/api/configs \
  -H "Content-Type: application/json" \
  -d '{
    "config_name": "project-config-demo",
    "config_type": "json",
    "config_value": {"enabled": true, "threshold": 3},
    "description": "Demo config"
  }'
```

创建承诺记录：

```bash
curl -X POST http://localhost:8080/api/commitments \
  -H "Content-Type: application/json" \
  -d '{
    "namespace": "ns-demo",
    "file_name": "commitment.pdf",
    "file_url": "https://oss.example.com/commitments/commitment.pdf"
  }'
```

上传带截图的封禁记录：

```bash
curl -X POST http://localhost:8080/api/bans/upload \
  -F "namespace=ns-demo" \
  -F "reason=## 封禁说明\n- 已附带截图" \
  -F "ban_start_time=2026-04-21T14:30:00Z" \
  -F "operator_name=alice" \
  -F "screenshots=@/tmp/sample.png"
```

查询 CompliK 全量事件：

```bash
curl "http://localhost:8080/api/complik-violations?include_all=true"
```

### 接口调试

可以将 `test/postman.json` 导入 Postman，快速体验当前仓库提供的接口。
