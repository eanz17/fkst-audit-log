# Audit Log → LLM 分析 → 异常告警：开源调研与 fkst 方案设计

> 目标系统：自动监控 audit log → 交给 LLM 分析 → 发现异常自动报警
> 生成日期：2026-07-09。开源调研共收集 43 个候选项目并逐一联网验证（仓库真实性、许可证、活跃度、管线覆盖度）。
> 配套阅读：[fkst-工作流程分析报告.md](fkst-工作流程分析报告.md)

---

## 一、需求拆解

这条管线有四个环节，评估任何现有项目都按此对照：

```text
① 采集        监听/读取 audit log（文件、syslog、云审计、K8s audit……）
② LLM 分析    把日志（或初筛后的可疑片段）交给 LLM 做语义理解
③ 异常判定    从 LLM 输出中得出"是否异常、多严重"的结构化结论
④ 告警        去重、限流后推送到 webhook/IM/工单，失败要重试
```

隐含的工程要求：**at-least-once 且幂等**（日志不能漏也不能重复轰炸）、**降噪**（不能每条日志都喂 LLM，成本和误报都受不了）、**LLM 输出不可信**（必须严格校验）、**自监控**（管线自己挂了也要有人知道）。

## 二、开源生态调研结论

**先说结论**：这个方向已经相当热闹，但**没有一个项目和"用 fkst 这类事件驱动 agent 运行时来编排"的思路相同**；现有项目分四类，端到端的完整方案只有两个，且都不是 fkst 形态。你的场景无论选哪条路，都有现成组件/参考实现可抄。

### 2.1 端到端完整方案（strong-fit，2 个）

| 项目 | 许可 / 活跃度 | 说明 |
|---|---|---|
| **[LogSentinelAI](https://github.com/call518/LogSentinelAI)** | MIT，56★，2026-07 仍活跃 | **与你的需求几乎逐字吻合**："LLM-powered security log analyzer"。采集（本地文件/SSH 远程/HTTP，批处理 + 实时采样两种模式）→ LLM 分析（声明式 Pydantic Schema 让 LLM 直接输出结构化 JSON，零正则；支持 OpenAI/Ollama/vLLM/Gemini/Claude）→ 严重级别判定 → CRITICAL 以上实时推 Telegram，另可写 Elasticsearch+Kibana。缺口：内置分析器面向 HTTP access log / auditd 等常见格式，自定义 audit log 需自己写 schema；社区小（个人项目规模） |
| **[SOCFortress CoPilot](https://github.com/socfortress/CoPilot)** | AGPL-3.0，504★，2026-07 高频迭代 | 开源 SOC 平台"single pane of glass"：Wazuh 采集审计日志 + Graylog 日志管理 + AI Analyst「Talon」对告警做端到端调查（IOC 富化、MITRE 关联、严重度评估、结构化报告），LLM 用 Claude 或本地 Ollama，且有匿名化代理在上云前替换 PII。缺口：整套栈较重（Wazuh+Graylog+Velociraptor+…），适合想要完整 SOC 的团队，不适合轻量场景 |

### 2.2 平台级部分覆盖（partial-fit，按环节分组）

**采集 + 规则判定 + 告警都强，缺 LLM 环节（做管线前段的最佳底座）**：

- **[Wazuh](https://github.com/wazuh/wazuh)**（GPLv2，16.1k★）：审计日志采集（auditd/FIM/云日志）+ 数千条规则 + 多渠道告警最成熟的开源底座。官方有"告警→ChatGPT 富化"PoC 和本地 Ollama RAG 威胁狩猎方案，但 LLM 环节全是胶水脚本，非产品内置。社区还有 [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server)（MIT，200★，54 个工具、带 RBAC/脱敏/审计）把 Wazuh 暴露给 LLM 对话查询。
- **[Falco](https://github.com/falcosecurity/falco)**（Apache-2.0，9.1k★，CNCF 毕业）：syscall + K8s/云审计日志（k8saudit、cloudtrail、gcpaudit、okta、github 等 27 个插件）的实时规则判定，结构化 JSON 告警输出——**如果你的 audit log 是 K8s/云审计，它是最顺手的事件源**。下游配 [falco-gpt](https://github.com/Dentrax/falco-gpt)（Apache-2.0，71★，约 3 年未更新，"Falco 事件→NATS 队列→OpenAI 修复建议→Slack"的最小参考实现）或 [Falco Vanguard](https://github.com/dadismad-com/falco-vanguard)（实验性，5★）。
- **[Matano](https://github.com/matanolabs/matano)**（Apache-2.0，1.7k★）：AWS 上的安全数据湖（50+ 日志源 → ECS 规范化 → Iceberg），Python detection-as-code + Sigma 规则，无 LLM。
- **[ElastAlert 2](https://github.com/jertel/elastalert2)**（Apache-2.0，1.1k★，活跃）：日志已在 ES/OpenSearch 时零代码做规则告警；社区常见玩法是 **LLM 把分析结论写回 ES 索引，ElastAlert 对该索引设规则触发告警**。
- **[Graylog](https://github.com/Graylog2/graylog2-server)**（SSPL，8.1k★）：老牌日志管理，7.0 起有实验性 MCP 端点供 LLM 直查日志。

**告警之后的 LLM 研判层（做管线后段）**：

- **[HolmesGPT](https://github.com/HolmesGPT/holmesgpt)**（Apache-2.0，2.8k★，CNCF Sandbox，极活跃）：agentic 根因分析，60+ 数据源 toolset（ES/Loki/Prometheus/云），结果回写告警源或 Slack；新 Operator Mode 可 24/7 主动巡检。**写个自定义 toolset 让它查你的 audit log 存储，就能复用整套分析+通知**。
- **[Robusta](https://github.com/robusta-dev/robusta)**（MIT，3.1k★）：K8s 告警富化 + playbook + 20+ 通知渠道，AI 分析插槽即 HolmesGPT。
- **[K8sGPT](https://github.com/k8sgpt-ai/k8sgpt)**（Apache-2.0，8k★，CNCF）：K8s 资源健康扫描 + LLM 解释；**其"送 LLM 前脱敏、返回后还原"的匿名化实现值得抄**。
- **[Keep](https://github.com/keephq/keep)**（MIT 核心，12k★）：开源告警中枢——去重/关联/AI 摘要/工作流路由，适合当管线末端的告警网关。

**SOAR / AI-SOC 编排层（把各环节串起来的工作流平台）**：

- **[Tracecat](https://github.com/TracecatHQ/tracecat)**（AGPL-3.0，3.7k★，极活跃）：开源 Tines/Splunk SOAR 替代，内置可自定义 AI agent（分诊/富化/调查）、100+ 连接器、Temporal 保证工作流可靠执行。**"audit log 事件 → LLM agent 分析 → 自动报警"这条链在它上面是开箱即用的形态**，但采集和异常基线要外接。
- **[Shuffle](https://github.com/Shuffle/Shuffle)**（AGPL-3.0，2.3k★）：2500+ 连接器的 SOAR，2.1.0 起 workflow 原生 LLM 节点；社区常与 Wazuh/TheHive 组三件套。
- **[Agentic SOC Platform](https://github.com/FunnyWolf/agentic-soc-platform)**（942★，404StarLink 项目，国产，极活跃）：SIEM 告警 → LLM 多 agent 研判（severity/verdict/调查报告）→ 案件聚合 → playbook 响应，中文生态友好。注意 README 自称 MIT 但根目录暂缺 LICENSE 文件。
- **[AI-SOC-Agent](https://github.com/M507/ai-soc-agent)**（MIT，43★，Black Hat 2025 配套，半年未更新）：SOC L1/L2 分层 AI agent profile + MCP 的参考实现，宣称单条告警 $0.18/50 秒。

**可观测性平台自带 AI（注意：AI 环节普遍是企业版）**：

- **[OpenObserve](https://github.com/openobserve/openobserve)**（AGPL-3.0，19.8k★）：单二进制日志平台，开源版覆盖采集+告警两端；但 RCF 异常检测和 AI Assistant 是 **Enterprise 版**。
- **[SigNoz](https://github.com/SigNoz/signoz)**（MIT 核心，28.5k★）：异常检测告警在 ee/ 目录且仅支持 metrics；LLM 侧靠官方 MCP server 外挂。
- **[Parseable](https://github.com/parseablehq/parseable)**（AGPL-3.0，2.4k★，Rust）：日志湖 + 内置统计式 anomaly/forecast 告警（开源可用）+ MCP server 对话查询。
- **[Netdata](https://github.com/netdata/netdata)**（GPL-3.0 agent，79.6k★）：边缘侧无监督 ML 异常检测（每指标 18 个 k-means 模型共识）+ 数百告警规则，可采集 systemd-journald；但 ML 作用于指标而非日志语义。
- **[Coroot](https://github.com/coroot/coroot)**（Apache-2.0，7.8k★）：eBPF 采集 + 日志模式聚类（新错误模式自动告警，开源可用）；LLM 根因分析是企业版。

### 2.3 研究/积木级（building-block，选摘）

- **[LogAI](https://github.com/salesforce/logai)**（BSD-3，816★，2023 年后基本停更）：Salesforce 的日志异常检测工具箱（解析/向量化/LSTM/LogBERT），**适合当 LLM 前面的初筛层**，但需自行封装。
- **[Drain3](https://github.com/logpai/Drain3)**（持续维护）：流式日志模板挖掘的事实标准——**做"日志聚类降噪、每类只喂 LLM 一个代表样本"的关键积木**。
- **[OpenSearch Anomaly Detection](https://github.com/opensearch-project/anomaly-detection)**（Apache-2.0，AWS 官方维护）：日志入 OpenSearch 后存储层原生 RCF 异常检测 + Alerting 联动。
- **[Anomstack](https://github.com/andrewm4894/anomstack)**（MIT，114★）："定时批处理 → PyOD ML 打分 → LLM agent 复核解释 → Email/Slack 告警"的最完整参考模板（面向指标）。
- 学术实现一批：LogPAI loglizer / deep-loglizer、DeepLog、LogBERT、LogLLM、LogPrompt、Nokia LogGPT（后两者无明确开源许可）。
- **[llm-log-analyzer](https://github.com/stratosphereips/llm-log-analyzer)**（Stratosphere IPS 实验室）：安全日志 LLM 分析实验脚本。

### 2.4 对你的启示

1. **"LLM 直读原始日志"是所有项目共同回避的做法**——太贵且误报高。通行分层是：规则/ML/模板聚类先筛（Wazuh 规则、Drain3 聚类、RCF），LLM 只研判可疑片段或已产生的告警。
2. **结构化输出是共识**：LogSentinelAI 用 Pydantic Schema 约束 LLM 输出，和 fkst archaudit 的"严格 JSON 数组 + fail-closed 解析"是同一个思想。
3. **脱敏值得做**：K8sGPT 的匿名化、SOCFortress 的 PII 代理、Wazuh MCP 的输出脱敏都在解决"审计日志含敏感信息，上云端 LLM 前要处理"——或者干脆用本地模型（Ollama/vLLM 是标配选项）。
4. **没有现成的"fkst 包"可以直接装**，但 fkst-packages 里的 `archaudit`（cron→LLM 审计→有界告警）+ `github-proxy`（出站代理：dry-run/幂等/限流/DLQ）就是这条管线的同构样板，改造成本低。

## 三、方案设计

### 3.1 选型建议（三条路线）

| 路线 | 适合场景 | 工作量 |
|---|---|---|
| **A. 纯 fkst 自建包族**（推荐，详见 3.2） | 你想要 fkst 的工程性质（可靠投递、崩溃即重启、conformance、dry-run 姿态、DLQ），日志源是本机/可挂载文件，告警走 webhook | 3 个小包，约 2-4 天出 MVP |
| **B. fkst + 开源组件混合** | 日志量大、需要规则初筛降噪：Wazuh/Falco 做采集+规则判定，产出的告警文件/webhook 由 fkst 消费做 LLM 研判与告警编排 | 部署 Wazuh/Falco + 1 个 fkst 包 |
| **C. 不用 fkst** | 只想最快跑起来验证效果 | 直接部署 LogSentinelAI（轻量）或 SOCFortress CoPilot（完整 SOC） |

下面重点展开 A，B 是 A 的采集端替换。

### 3.2 方案 A：fkst 审计日志监控包族设计

#### 3.2.1 包拓扑（照抄 fkst-packages 的分层纪律）

```text
audit-watcher   (flat, stateless_adapter)      —— ① 采集与批组装
audit-analyzer  (composed, judgment_pipeline)  —— ②③ LLM 分析与判定，event_deps = ["audit-watcher", "alert-proxy"]
alert-proxy     (flat, stateless_adapter)      —— ④ 告警出站边界（仿 github-proxy）
```

事件流：

```text
[raisers]
 audit-watcher/raisers/log_watch.lua   file_watch glob=<审计日志目录>/*.log → audit_file_changed
 audit-watcher/raisers/sweep_poll.lua  cron 10m → audit_sweep_tick        （轮询兜底 + 活性心跳）

[audit-watcher.collect]  consumes: audit_file_changed, audit_sweep_tick
   读文件增量 → 预过滤/≤8 KiB 分批 → watcher 预脱敏
   → raise bounded inline 脱敏正文、schema 与 full SHA-256 的 v3 事件（cache 仅诊断）
   → produces: 自有队列 audit_batch

[audit-analyzer.analyze]  consumes: audit-watcher.audit_batch（跨包消费用限定名，
   如 archaudit 消费 idle-detector.system_idle）
   默认关闭；校验 payload → 二次幂等脱敏 → 显式启用时 spawn_codex_sync
   → fail-closed 解析 JSON findings → 事实核验 → 达阈值的 finding
   → produces: alert-proxy.alert_request（跨包生产：alert-proxy 的 send 部门需
   published_seam = {"alert_request"} 授权，仿 github-proxy 的请求队列模式）

[alert-proxy.send]  consumes: alert_request
   去重（内容派生 dedup_key + cache marker + with_lock）→ FKST_ALERT_WRITE=1 门控
   → exec_sync curl 发 webhook（飞书/Slack/Telegram）→ 失败 error() 走引擎 retry
[每个包一个 dead_letter 部门 + alert-proxy 把 DLQ 升级为兜底通知]
```

#### 3.2.2 关键设计点与代码骨架

**（1）采集：file_watch 的语义要吃透。** 引擎在文件 (长度, mtime) 变化时发 `{path}` 事件（追加写日志每次变化都会触发），但**不带增量内容**——读到哪里由包自己管。offset 存 cache 是 best-effort（`<RT>` 清空即丢），丢了就回退到"重读尾部 N 行"，重复告警由 alert-proxy 的 dedup 吸收（at-least-once 哲学的正确用法）：

```lua
-- audit-watcher/departments/collect/main.lua（骨架）
local core = require("core")
local audit_redaction = require("audit_shared.redaction")
local function raise_batches(path, from_offset, to_offset, suspicious)
  -- core.chunk_lines 把批正文限制在 8 KiB，为可靠事件的 JSON 转义和元数据留余量。
  local chunks = core.chunk_lines(suspicious)
  for index, chunk in ipairs(chunks) do
    local analysis_chunk = audit_redaction.redact_log_lines(chunk)
    -- batch_id 包含 v3 修订号、范围、序号和正文 SHA-256 128-bit 前缀；
    -- file_key 同样使用路径 SHA-256 128-bit 前缀。
    local batch_id = core.batch_id(path, from_offset, to_offset, index, analysis_chunk)
    -- 同一脱敏正文的 1h scratch 副本只供本地诊断。
    cache_set(core.batch_content_key(batch_id), analysis_chunk,
      core.batch_cache_ttl_seconds())
    local line_count = select(2, analysis_chunk:gsub("\n", "\n")) + 1
    raise("audit_batch", {
      schema = "audit-watcher.batch.v3",
      batch_id = batch_id,
      source_path = core.utf8_safe_truncate(path, 512),
      line_count = line_count,
      byte_range = { from = from_offset, to = to_offset },
      content_schema = "audit-redaction.v1",
      content = analysis_chunk,
      content_checksum = core.checksum(analysis_chunk), -- 完整 64-hex SHA-256
      dedup_key = "audit-batch/" .. batch_id,
    })
  end
  return #chunks
end
```

**（2）LLM 分析：整段照抄 archaudit 的三件套**——严格 prompt、fail-closed 解析、事实核验：

```lua
-- audit-analyzer/core.lua（骨架）
function M.build_prompt(log_lines, max_findings)
  return table.concat({
    "You are a security audit-log analyst. Analyze ONLY the log lines below.",
    "Identify anomalies: privilege escalation, unusual auth failures, suspicious",
    "process/file access, off-hours admin activity, data exfiltration patterns.",
    "Do not invent events not present in the lines. Do not report normal operations.",
    "Return strict JSON only: an array of at most " .. max_findings .. " objects.",
    'Schema: {"severity":"critical|high|medium","category":"...","evidence_line":"<脱敏输入中的完整行>",'
      .. '"why":"...","recommended_action":"..."}',
    "Return [] if nothing is anomalous.",
    "", "=== LOG LINES ===", log_lines,
  }, "\n")
end

function M.parse_findings(stdout)
  -- 仿 archaudit.parse_findings_json：必须是严格 JSON 数组，逐字段限长校验
  -- 解析失败一律 error("audit-analyzer: malformed-json: ...") 走 retry/DLQ
end
```

```lua
-- audit-analyzer/departments/analyze/main.lua（核心段）
local function batch_content(p, batch_id)
  if p.schema == "audit-watcher.batch.v3"
      or p.schema == "audit-watcher.batch.v2" then
    if p.content_schema ~= "audit-redaction.v1" then
      error("audit-analyzer: invalid-batch-content: unknown redaction schema", 0)
    end
    if type(p.content) ~= "string" or p.content == ""
        or #p.content > core.max_batch_content_bytes() then
      error("audit-analyzer: invalid-batch-content: invalid inline content", 0)
    end
    local expected = tostring(p.content_checksum or "")
    local valid_checksum = expected == core.checksum(p.content)
    if p.schema == "audit-watcher.batch.v2" then
      valid_checksum = valid_checksum or expected == core.legacy_checksum(p.content)
    end
    if expected == "" or not valid_checksum then
      error("audit-analyzer: invalid-batch-content: batch checksum mismatch", 0)
    end
    return p.content
  end
  if p.schema == "audit-watcher.batch.v1" then
    local legacy = cache_get("audit-watcher/batch/" .. batch_id)
    if legacy == nil then
      error("audit-analyzer: legacy-batch-content-missing: batch=" .. batch_id, 0)
    end
    return legacy
  end
  error("audit-analyzer: unknown-schema: " .. tostring(p.schema), 0)
end

function pipeline(event)
  local p = event.payload or {}
  local batch_id = tostring(p.batch_id or "")
  local lines = batch_content(p, batch_id)
  if read_env("AUDIT_ANALYZER_CODEX_ENABLED") ~= "1" then return end
  -- 共享脱敏器是幂等的；analyzer 再执行一次作为纵深防御。
  local analysis_lines = core.redact_log_lines(lines)
  local result = spawn_codex_sync({
    prompt = core.build_prompt(analysis_lines, 5),
    sandbox = "read-only",
    timeout = 600,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    error("audit-analyzer: codex-" .. (result.exit_code == 124 and "timeout" or "nonzero"))
  end
  local findings = core.parse_findings(result.stdout)
  for _, f in ipairs(findings) do
    -- 反幻觉核验：evidence_line 必须等于脱敏分析文本中的一整行。
    if core.evidence_present(f, analysis_lines) and f.severity ~= "medium" then
      raise("alert-proxy.alert_request", {
        schema = "alert-proxy.alert.v1",
        severity = f.severity, category = f.category,
        summary = f.why, evidence = f.evidence_line,
        action = f.recommended_action, source_path = p.source_path,
        dedup_key = core.alert_dedup_key(f, batch_id), -- category+evidence/batch digest
      })
    end
  end
end
```

`audit-watcher.batch.v3` 是当前主路径，`content_checksum` 为完整 SHA-256；v2 仅作 inline 滚动兼容，可校验旧十进制 DJB2 或过渡 SHA-256；v1 仅作 cache 兼容，miss 必须进入 retry/DLQ。文件指纹为 `v2:<size>:<full SHA-256>`，file/batch key 用 SHA-256 的 128-bit 前缀，batch 内部修订为 v3。`source_path` 最长 512 bytes；Aevatar 完整 scope 只参与查询身份，进入 durable/display path 前按身份规则截短。

≤8 KiB inline 正文是当前 64 KiB 引擎上限内的 bounded transition/隐私取舍，不是长期推荐事实模型。长期应将预脱敏正文原子写成 explicit host filesystem fact，reliable payload 只保留 `source_ref`、schema、digest 与小控制字段，analyzer 消费时回源校验。

analyzer 默认关闭且不参与确定性的 stability → issue → devloop 主路径。启用后，通过 evidence 门禁的 finding 会再次脱敏，只把 `redacted-v3-sanitized-output` JSON 放入 24h scratch cache；`lease_generation>1` replay 会绕过旧 scratch 读取并可能重跑 Codex，因此不能承诺重放不重算。模型决定也没有持久化为 explicit fact，故该支路不是端到端 critical reliable path。

**（3）LLM 出口的两种接法**（详细依据见分析报告 §5）：

- **路 A（引擎正统路径）：`spawn_codex_sync`**。自带并发 permit 池、超时 SIGKILL、日志留痕、`error_class` 归类。引擎会原样记录 stdout，repo 内没有关闭开关；`read-only` 仍允许读取宿主可见文件，所以启用前必须用 OS/container 收窄可读面。
- **路 B（任意 LLM API）：`exec_sync` + curl**。引擎无 HTTP 原语，这是唯一直连方式，合法且被审计（每次调用留 `EVENT=external_command` 日志）。注意三个坑：`json` 没有 encode（请求体用 `file.write` 写临时文件 + `curl -d @file`）；stdin 恒为 /dev/null（不能 `-d @-`）；限流自己配 `FKST_RATE_POOL_CURL=<burst>,<refill/min>`，拿不到 token 会阻塞，要和 `stall_window` 匹配。当前 collect 已在可靠发布前预脱敏，analyzer 仍会幂等脱敏；**日志含敏感信息时继续优先本地模型**（Ollama/vLLM 的 OpenAI 兼容端点），以进一步缩小外发面。

**（4）告警出站：整体仿 github-proxy 的姿态纪律**：

```lua
-- alert-proxy/departments/send/main.lua（核心段）
function pipeline(event)
  local p = event.payload or {}
  local marker_key = "alert/sent/" .. tostring(p.dedup_key)
  with_lock("alert/" .. tostring(p.dedup_key), function()
    if cache_get(marker_key) then return end          -- 幂等：重投不重发
    local body_path = "/tmp/fkst-alert-" .. tostring(now()) .. ".json"
    file.write(body_path, core.render_webhook_body(p)) -- 手工拼 JSON（无 json.encode）
    local r = exec_sync({
      cmd = "curl -sS --fail-with-body -X POST -H 'Content-Type: application/json' -d @"
            .. body_path .. " \"$ALERT_WEBHOOK_URL\"",
      timeout = 15,
    })
    if r.exit_code ~= 0 then
      error("alert-proxy: webhook-failed: exit=" .. tostring(r.exit_code))  -- 走引擎 retry
    end
    cache_set(marker_key, "1", 24 * 3600)             -- 24h 去重窗口
  end)
end
```

配套纪律：`FKST_ALERT_WRITE=1` 作为唯一真发开关（未设置只打 `dry-run: would alert` 日志——上线前可全链路空跑验证）；severity 分级路由（critical 走电话/值班 webhook，high 走 IM）；`retry = { max_attempts = 5, base = "30s", cap = "10m" }`，耗尽进 DLQ，`dead_letter` 部门再用**独立的兜底通道**（如另一个 webhook）发"告警发送失败"的元告警。

**（5）自监控（管线挂了谁报警？）**——这是 fkst 相比裸脚本的最大优势，直接复用两个机制：

- `audit_sweep_tick`（cron 10m）除了兜底扫描，还检查 `cache_get("audit/last_batch_at")` 距今是否超过阈值，超过则直接 raise 一条"采集环节沉默"的 alert_request——仿 archaudit 的 producer-liveness 契约（"最多沉默 30m、最迟 24h 必产出"）。
- `fkst.observe()` 读引擎投递账本：DLQ 非空、队列积压超阈值时发元告警（idle-detector 的 observe_port 有现成读法可抄）。

#### 3.2.3 方案 B 变体：Wazuh/Falco 前置

日志量大或需要成熟规则库时，把 ① 和初筛交给专业工具：

```text
Wazuh（或 Falco + falcosidekick）→ 告警写入 JSON 文件目录（两者都原生支持）
  → fkst file_watch 监听该目录 → audit-analyzer 只研判"已是告警"的事件（量小、上下文密度高）
  → alert-proxy 出站
```

这正是 falco-gpt / Wazuh-LLM-PoC 的形态，但用 fkst 替换它们的薄弱环节（无重试、无幂等、无 DLQ、无 dry-run）。LLM prompt 也从"找异常"简化为"研判这条告警是真是假 + 给出处置建议"，误报率和成本都更低。

### 3.3 落地步骤建议

1. **第 1 天**：`fkst-framework init-package-repo` 建包仓（或直接在 fkst-packages 结构上加包）；写 `alert-proxy`（最简单、可独立测试，`scripts/run.sh run alert-proxy send '{"payload":{...}}'` 空跑 dry-run）。
2. **第 2 天**：写 `audit-watcher`，用 `fkst.test.mock_command` + fixture 日志文件把增量读取/轮转/预过滤全部单测覆盖（test 模式未 mock 的外部命令 fail-closed，天然逼你写可测代码）。
3. **第 3-4 天**：写 `audit-analyzer`，prompt 先用真实历史日志离线调（直接 `codex exec` 命令行迭代 schema），再接入管线；跑 `scripts/run.sh test` + conformance。
4. **上线**：先 dry-run 姿态跑一周看日志（`FKST_ALERT_WRITE` 不设置），核对 LLM 判定质量和成本，再打开真发开关；同时把 LogSentinelAI 的 prompt/schema 设计翻出来对照抄优点（它的 auditd 分析器 schema 可直接借鉴）。

### 3.4 风险与对策

| 风险 | 对策 |
|---|---|
| LLM 成本失控 | 预过滤（关键词/规则/Drain3 聚类）+ 批处理窗口 + 每轮 finding 上限；方案 B 前置规则引擎可再降一个数量级 |
| LLM 幻觉误报 | evidence 行必须逐字等于脱敏分析文本中的完整一行 + severity 阈值；模型决定未落 explicit fact，replay 可能重算 |
| 敏感日志外泄 | watcher 发布前脱敏、Aevatar scope/source_path 截断、analyzer 再脱敏；但 Codex stdout 原样落 log，启用必须用 OS/container 隔离可读面 |
| 告警风暴 | category+evidence/batch SHA digest（无天桶）+ 24h sent marker + `FKST_RATE_POOL_CURL` 限流 |
| 管线自身故障静默 | cron 心跳 + `fkst.observe()` DLQ 巡检 + 死信升级为独立通道元告警 |

---

*调研方法：3 个联网调研 agent 分别从「LLM 日志异常检测」「SIEM/SOC + AI」「可观测性平台 AI」三个角度扫描，35 个候选去重后逐一用独立 agent 打开仓库验证（真实性/许可证/stars/最近活跃/管线覆盖），另做一轮遗漏检查补充 8 个再验证，共 43 个项目全部核实。上文陈述的 stars 与活跃度为 2026-07-09 快照。*
