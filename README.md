# 微服务漏洞复现与动态风险量化系统（论文可复现实验版）

这是在原 `qiqi541/my-project` 基础上重建的实验项目。它保留了 Docker 微服务、四类漏洞探测、Kafka、DRS 和可视化大屏，同时修复了原项目中无法复现 WAF 消融、无法证明 Kafka 最终落库、无法计算端到端时延、报告结果硬编码等问题。

> 仅允许在本人控制的隔离虚拟机中用于教学与论文实验。不要将 `vuln-web` 暴露到公网，也不要对未授权目标运行探测脚本。

## 1. 主要改进

- WAF 通过环境变量开关，场景 A/B 可以重复运行。
- Producer 发送原始证据；Consumer 执行 DRS 计算，符合 Actor/Planner 分层。
- 每条事件有 `event_id`、`run_id`、场景和完整时间戳。
- Kafka 使用 `acks=all` 和发送确认；Consumer 在 SQLite 落库后才提交 offset。
- SQLite 使用唯一主键、WAL、FULL synchronous 和幂等插入。
- 压测以最终唯一落库数计算丢失率。
- Dashboard 使用只读数据库连接和真实 AJAX 增量刷新。
- 实验报告、CSV、JSON 和论文图表由数据库自动生成，不写死预期结果。
- AHP 权重计算和论文四类 DRS 分值有自动化测试。

## 2. 虚拟机要求

- Ubuntu 22.04/24.04，建议 4 核 CPU、8 GB 内存；
- Docker Engine 24+；
- Docker Compose v2；
- 首次构建需要访问 Docker Hub 和 PyPI；
- 至少预留约 8 GB 磁盘空间。

本项目改用 `confluentinc/cp-kafka:7.5.15` 与 `cp-zookeeper:7.5.15`。Confluent Platform 7.5 包含 Apache Kafka 3.5 系列；原项目的免费 Bitnami 镜像目前已不再稳定公开提供。

## 3. 初始化

```bash
cp .env.example .env
nano .env                     # 修改 Dashboard 口令和 Secret
mkdir -p data results
chmod +x scripts/*.sh
docker compose build
```

如从宿主机以外访问 Kafka，把 `.env` 中 `KAFKA_HOST` 改成虚拟机 IP。仅通过容器内部实验时保持 `localhost` 即可。

## 4. 快速演示

```bash
docker compose --profile demo up -d --build
docker compose ps
```

访问：

- Dashboard：`http://虚拟机IP:5001`
- 靶机健康状态：`http://虚拟机IP:5000/health`

查看日志：

```bash
docker compose logs -f producer consumer
```

停止：

```bash
docker compose --profile demo down
```

## 5. 论文实验

### 5.1 365 轮、1825 条计划样本

```bash
ROUNDS=365 WAF_ENABLED=false bash scripts/run_full_experiment.sh
```

默认每轮包括两次弱口令尝试、一次 SQLi、一次反射型 XSS 和一次 Padding Oracle 行为检测，共 5 条证据。脚本会等待数据库达到 `365 × 5` 条唯一记录后才导出结果。

### 5.2 WAF 消融：500 + 500 条

```bash
ABLATION_ROUNDS=500 bash scripts/run_ablation.sh
```

场景 A 关闭 WAF，场景 B 开启 WAF。两组使用不同 `run_id`，自动计算静态模型与 DRS 的误报率。

### 5.3 SQLite 与 Kafka 1000 条高并发对比

```bash
STRESS_TOTAL=1000 STRESS_THREADS=10 bash scripts/run_stress.sh
```

Kafka 结果中的 `persisted` 是 Consumer 最终写入数据库的唯一记录数。脚本退出码为 0 才表示本次计划记录全部持久化；实验结果会因虚拟机负载而变化。

## 6. 输出文件

每次实验会在 `results/` 生成：

- `*-events.csv`：完整原始证据和三类时延；
- `*-summary.json`：所有统计量；
- `*-report.md`：可核对的实验报告；
- `*-latency.png`：各漏洞端到端平均/P95 时延；
- `*-risk-distribution.png`：DRS 分布；
- `stress-*.json/csv/md`：耦合与解耦压测结果及可直接核对的表格。
- `*-ablation.png/json`：WAF 消融对比图和两组统计数据。

论文中的数字应只从这些文件复制，并注明 `run_id`。

## 7. 本地测试

不启动 Docker 也可以检查公式和报告统计代码：

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall common producer consumer dashboard experiments tools vuln-web
```

完整部署检查：

```bash
docker compose config
docker compose up -d --build zookeeper kafka vuln-web consumer dashboard
docker compose ps
```

## 8. 数据安全与清理

`.env`、数据库和实验结果默认不会进入 Git。清理本地实验数据必须显式确认：

```bash
bash scripts/reset_experiment_data.sh --yes
```

Dashboard 认证只适合隔离实验网络，不应视为生产级身份系统。Kafka 当前为 PLAINTEXT，也是为了封闭虚拟机中的可重复实验。

## 9. 论文表述边界

请先阅读 [PAPER_ALIGNMENT.md](PAPER_ALIGNMENT.md)。尤其注意：

- AES-CBC 实验不应表述成 SM 系列商用密码算法实现；
- 当前验证的是 Padding Oracle 行为存在，不是明文恢复；
- XSS 是反射型，不是存储型；
- 215ms、0% 丢失、100%→0% 误报率都必须以虚拟机实测结果为准。
