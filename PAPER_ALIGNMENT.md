# 论文内容对齐说明

本文件用于防止论文文字再次超出代码和原始数据能够证明的范围。最终论文中的所有实验数值，应从 `results/` 中同一 `run_id` 的 CSV、JSON 和图表复制。

## 已与代码一致的内容

- DRS 公式：`δ × [0.6 × Impact + 0.4 × (10 - AC)]`。
- SQL 注入、弱口令、反射型 XSS、Padding Oracle 行为检测四类用例。
- Kafka 事件总线、Consumer 决策计算、SQLite 持久化和 Dashboard 展示。
- WAF 开启与关闭的两组可控场景。
- HIGH、MEDIUM、LOW、INFO 四档阈值。
- 每条证据具备唯一 ID、批次 ID、场景、原始响应和全链路时间戳。

## 论文必须同步修改的文字

1. **Kafka 镜像**：改为“Confluent Community 7.5.15 所含 Apache Kafka 3.5 系列”。原免费 Bitnami 镜像已不再稳定提供。
2. **AHP 标度**：1.5 属于连续比率标度，不应再称为严格的整数 1–9 Saaty 标度。二阶矩阵 `CR=0` 是结构性质，只能说明矩阵互反一致，不能单独证明专家赋权具有充分外部效度。
3. **计算位置**：Producer 负责 Actor 探测和原始证据生成；Consumer 负责 Planner 的 DRS 计算、定级和持久化。
4. **XSS 类型**：当前实现是反射型 XSS，不是存储型 XSS。
5. **Padding Oracle 结论**：当前实验验证“可区分的填充错误响应/Oracle 行为存在”，没有执行明文恢复，因此不得写成“成功恢复密文原文”。
6. **商用密码表述**：AES-CBC 是通用密码算法仿真，不是我国 SM2/SM3/SM4 算法实现。论文宜写“密码应用安全缺陷仿真”；如要直接支撑密评结论，应另增 SM4-CBC 合规场景。
7. **Dashboard**：现在确实通过 `/api/data` 每 3 秒 AJAX 更新；不要再写成“页面刷新”。
8. **数据库读取**：Dashboard 使用 SQLite URI 只读连接；Consumer 使用 WAL、FULL synchronous、幂等主键和提交后 Kafka offset commit。

## 三组实验的真实口径

### 365 轮功能与时延实验

运行：

```bash
ROUNDS=365 WAF_ENABLED=false bash scripts/run_full_experiment.sh
```

默认字典有一次失败口令和一次成功口令；加上 SQLi、XSS、Padding Oracle，每轮产生 5 条证据，理论计划值为 `365 × 5 = 1825`。论文只能在导出的唯一落库记录确实等于 1825 时写“采集 1825 条”。

时延定义：

- 探测响应时延：`response_received_at - request_started_at`；
- Kafka/决策管道时延：`persisted_at - emitted_at`；
- 端到端时延：`persisted_at - request_started_at`。

论文应同时报告平均值、P50、P95、P99、样本量、虚拟机配置和 `run_id`。不得继续写死 215ms。

### WAF 消融实验

运行：

```bash
ABLATION_ROUNDS=500 bash scripts/run_ablation.sh
```

脚本分别产生 500 条无 WAF 和 500 条有 WAF 的 SQLi 记录。静态模型的误报和 DRS 误报均由带有真实标签的记录计算。误报率定义为 `FP / (FP + TN)`；没有负样本的场景不计算 FPR。

### 1000 条高并发实验

运行：

```bash
STRESS_TOTAL=1000 STRESS_THREADS=10 bash scripts/run_stress.sh
```

Kafka 组的丢失率按数据库中该 `run_id` 的唯一持久化记录计算，不再按 `producer.send()` 是否立即抛异常计算。只有 `persisted == planned` 时，论文才能写该次实验为 0% 丢失。

## 仍需人工完成的论文工作

- 在虚拟机实际运行三组实验，并保留 `results/` 原始文件。
- 用自动生成的 PNG 替换论文图 5-2，并用 JSON/CSV 更新表 5-2、表 5-3。
- 删除原稿中 171.8ms、215ms、124ms 等彼此冲突的数字，以当前实验数据为准。
- 补充真实参考文献，不得保留占位句。
- 报告 Docker、CPU、内存、内核、镜像、Python 包版本及实验日期。

