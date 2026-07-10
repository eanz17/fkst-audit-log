# fkst 工作流程分析报告

> 分析对象：`~/Code/fkst-substrate`（引擎）与 `~/Code/fkst-packages`（官方包库）
> 生成日期：2026-07-09（基于两仓库 dev 分支当前工作区）

---

## 1. fkst 是什么：一句话与双仓库分工

fkst 是一个**受监督的事件驱动运行时**：Rust 引擎调度 Lua 编写的"部门"（department），部门消费事件队列里的事件，可以在处理中拉起 codex CLI（LLM agent）子进程做判断性工作，再把结果作为新事件抛回队列。核心比喻是"三级公司"：

- **Company**（一级）= supervisor 进程 + `fkst-framework supervise` 事件运行时 + 启动期验证过的固定行为图；
- **Department**（二级）= `departments/<dept>/main.lua`，暴露 `M.spec` 和 `pipeline(event)`，**无持久状态**；
- **Person**（三级）= 一次 `codex exec` 子进程，实例间不直接通信。

代码分为两个边界严格的仓库：

| 仓库 | 角色 | 内容 |
|---|---|---|
| `fkst-substrate` | 引擎（衬底） | Rust supervisor、事件运行时、Lua SDK、可靠投递、conformance 检查。**不含业务 Lua 包** |
| `fkst-packages` | 官方包库（"库 B"） | 纯 Lua 行为层包（departments/raisers/tests）+ 5 个共享库。**不含引擎 Rust 代码，不存宿主状态** |

引擎通过 `--package-root` / `FKST_PACKAGE_ROOTS` 在启动时注入包；包之间只通过事件队列通信，禁止跨包 `require`。

## 2. 三层稳定性模型（Tier I / II / III）

fkst-substrate 用"稳定性分层"控制变更风险（[SPEC.md](~/Code/fkst-substrate/SPEC.md)）：

- **Tier I — 进程根 supervisor**（`crates/fkst-supervisor`，仅 `main.rs` 95 行 + `process_tree.rs` 52 行）：定位 framework 二进制、启动 `fkst-framework supervise`、继承 stdout/stderr、处理信号（SIGINT→130 / SIGTERM→143）、收割子进程。它不扫描图、不解析事件、不知道 Department 的存在，且**不依赖任何 workspace 内部 crate**。`scripts/verify.sh` 强制整个 crate 源码**总行数 ≤ 150**（当前 147，"must stay readable in one sitting"）——这是信任基最小化的机械执行：任何想把调度逻辑塞进进程根的改动都会撞上 CI 硬失败。
- **Tier II — 身份锚点**：`SPEC.md` + conformance 入口 + 不可覆盖 gate。只回答"系统是什么"，禁止记录运行时事实（当前分支、队列深度、pid 等）。Tier II 改动要求深度共识、独立 review、conformance 通过——单个 codex 实例不能凭自身判断绕过 gate。
- **Tier III — 引擎运行时 + 注入的 Lua 图**：`fkst-framework`、`fkst-common` 是引擎代码；业务 Lua 包是可替换的外部行为层。

第四个 crate `fkst-update` 是独立的 verify-and-swap 部署客户端（从 GitHub Releases 下载、SHA-256 校验、原子替换二进制），刻意不拥有 accepted-state/回退/健康门控——发布安全是外部策略，不在热路径上。

## 3. 引擎 CLI surface

`fkst-framework` 的完整子命令（以 `main.rs` 的 `CliCommand` 为准）：

```text
run <lua> --project-root <HOST> --package-root <PKG>... --owner-namespace <id> --event <json>
supervise --project-root <HOST> [--package-root <PKG>...] --framework-bin <path>
conformance / config / boundary-resources          # 只读自省与 gate
test [--report-json <p>] [--coverage <dir>]        # Lua 测试 runner（含 mock/cassette/覆盖率）
rate-acquire <pool> / rate-exec <pool> -- <prog>   # 主机级限流令牌
host lock / deps [lock|fetch] / manifest composed-deps / init-package-repo
--self-test
```

关键点：`supervise` 是常驻调度进程，但**每个事件的实际处理都 spawn 一个新的 `fkst-framework run` 子进程**，在独立 Lua state 中执行 `pipeline(event)`——部门天然无进程内状态，崩溃恢复代价被设计为"从零重来"。

## 4. 核心工作流：事件的一生

### 4.1 事件源（Raiser）

Raiser 是只返回声明的 Lua 文件，当前**只有两种类型**（未知 `type` 在 parse 期 fail-closed）：

```lua
{ type = "cron", interval = "30m", produces = "archaudit_tick" }
{ type = "file_watch", glob = "logs/audit/*.jsonl", produces = "audit_file_changed" }
```

- **cron**：首次触发带确定性 jitter；错过的 tick 合并为一次。source_ref 是 `"{name}/slot/{按interval取整的槽位ms}"`——同一逻辑 tick 派生**稳定的 delivery_id**，天然去重。
- **file_watch**：notify 文件系统事件 + 5 秒轮询双通道；文件**新建或 (长度, mtime) 变化**时发出 `{path = "<绝对路径>"}` 事件（[source_runner.rs:115](~/Code/fkst-substrate/crates/fkst-framework/src/supervise/source_runner.rs)）。source_ref 是 `"{路径}/len/{L}/mtime/{T}"`——文件的"变更版本"编入投递身份，同版本跨重启幂等。**启动时全量扫描已存在的匹配文件**（这是崩溃恢复的关键），跨进程重启的业务幂等由消费方负责。

### 4.2 部门（Department）

```lua
local M = {}
M.spec = {
  consumes = { "idle-detector.system_idle", "archaudit_tick" },  -- 跨包用 pkg.queue 限定名
  produces = { "github-proxy.github_issue_create_request" },
  stall_window = "10m",     -- 可靠投递租约窗口（不是子进程 kill 超时）
  retry = { max_attempts = 12, base = "5s", cap = "30s" },  -- 或 false
  -- 可选：fanout（广播队列）、ephemeral（降级为非可靠）、published_seam（对兄弟包公开的入口队列）、graph_json
}
function pipeline(event)  -- event = { queue, payload, ts }
  raise("some.queue", payload)  -- 引擎强制 raise ⊆ produces ⊆（自有队列 ∪ 兄弟 published_seam）
end
return M
```

### 4.3 端到端时序

```text
raiser 触发（cron tick / file_watch 变化）
  → DeliveryRouter.publish（带确定性 SourceRef）
  → 可靠订阅：先在单写事务内写入 redb delivery store（查重→插入），commit 后才内存唤醒 consumer
     （"durable commit 先于内存唤醒"：唤醒可丢，账本不丢，1s tick 兜底）
  → consumer lease 到期/到点的 delivery（准入受 FKST_MAX_IN_FLIGHT_PER_DEPT 等背压约束，先准入后耗租约）
  → spawn 子进程：fkst-framework run <dept main.lua> --event <json>（独立进程组）
  → 独立 Lua state 执行 pipeline(event)；SDK 调用：file/json/git/lock/exec/codex/log/raise
  → 子进程退出：stdout 尾部的 RAISED-AUTH: <一次性token> <base64-json> 帧被父进程解析
     （token 由父进程注入 env、在加载用户代码前移除——Lua 侧不可见，防 log 伪造事件）
  → exit 0 且所有 RAISED 发布成功 → ack（即删记录）；否则 → retry（指数退避）
  → 重试超过 max_attempts → 移入 redb 死信表（compact 墓碑），best-effort 发布 dead_letter 事件
```

投递语义是 **at-least-once-until-ack**（无 exactly-once）：重试会重发 raised 事件，靠三层确定性 delivery_id 折叠重复——source 事件按 cron 槽位/文件版本；raised 事件按 `payload.dedup_key`（跨父事件折叠，先到者胜）或继承的 source_ref；兜底用 parent 哈希 + 序号。

### 4.4 事实源哲学与恢复模型

这是 fkst 最有个性的设计：

- **内存队列是瞬时的**；可靠性由 `FKST_DURABLE_ROOT` 下的 redb store 承担（lease + lease_generation fencing 保证跨重启不双 ack）。
- **runtime root（`<RT>`）全部是 scratch**：`locks/`（fcntl 锁，进程死即释放）、`marks/`（`once` 标记）、`cache/`（best-effort KV）、`worktrees/`、`logs/`。清空后系统必须能重推。
- **跨 pipeline 的稳定事实只能来自**：git refs/commits、host 文件系统边界、外部源（如 GitHub issue）。"完成态"落到 git commit 或外部系统，不落引擎内部。
- **恢复模型**：崩溃等价于从零重来。cron 下一拍 / file_watch 启动全量扫描从 durable 源重推事件，确定性 delivery_id 保证在途的重复入队是 no-op；业务幂等由包保证（内容派生 dedup_key、写边界 marker、`once`）。
- 订阅者长期缺席（如包下线）的 pending delivery 会在超过 `FKST_SUBSCRIBER_ABSENT_DELIVERY_BUDGET`（默认 168h）后进入**可重放 DLQ**，订阅者回归后可 redrive。

## 5. Lua SDK：部门能做什么

固定 surface，不可动态扩展（新增 SDK 函数需 evidence + 深度共识 + conformance 覆盖）：

| 类别 | 原语 | 要点 |
|---|---|---|
| LLM | `spawn_codex_sync(opts)` / `spawn_codex`+`await_all`、`fkst.codex_runs()` | 实际执行 `codex exec --dangerously-bypass-approvals-and-sandbox [-C <worktree>] -`，**prompt 经 stdin 传入**，stdout/stderr 全量捕获；默认 3600s 墙钟超时（超时 SIGKILL 全进程组，exit 124）。两层闸门：`<RT>/codex-permits` fcntl permit 池（默认 20 槽）+ rate shim（codex 内部再调 gh 等命令也被限流包裹）。**GH/GITHUB 系凭证在 spawn 前被清洗**。带 worktree 的调用有崩溃收养机制（同 dedup_key 的重投会收养正在跑的 codex 而非重复拉起）。失败带 `error_class`：quota-exhausted / auth-degraded / provider-unavailable / provider-throttle |
| 外部命令 | `exec_sync(cmd|opts)`（`/bin/sh -c`）、`exec_argv{argv=...}`（免 shell，防注入） | **无命令白名单、无网络限制**，但每次执行写一条 `EVENT=external_command` 审计日志；stdin 恒为 /dev/null；`timeout` 到期 killpg。限流按首个程序名匹配 `FKST_RATE_POOL_<NAME>=<burst>,<refill/min>` 主机级令牌桶（跨进程 flock 共享），拿不到 token **无限期阻塞退避**。可选 `read_coalesce` 读合并（仅幂等读、ttl≤300s）。注意 `exec_argv` 已实现但尚不在 SPEC 固定列表内 |
| 协调 | `with_lock(name, fn)`、`once(key, fn)`、`cache_set/get/expire` | 共用 key 合约（相对路径、段匹配 `[A-Za-z0-9._-]+`）。**`once` 有能力门禁**：仅 `persistence_class = "saga"` 的包可用，其他包调用直接报错。cache 需要 read-compare-write 原子性时必须外层套 `with_lock` |
| Git | `setup_worktree`（建隔离 worktree + candidate 分支）、`count_worktrees`、`list_orphan_worktrees`、`git_log_count/grep`（用 commit message 当持久事实查询） |
| IO/观测 | `file.read/write/exists/list`（无路径沙箱）、`json.decode`（**没有 encode**）、`toml.decode`、`log.*`（结构化写 stderr，CR/LF 转义防协议伪造）、`now()`、`t()`（本地化）、`restricted_lua_load`（空 `_ENV` 沙箱评估小段声明式 Lua）、`graph_json()`（需授权）、`fkst.observe()`（redb 投递账本快照：队列深度/在途/DLQ） |
| 事件 | `raise(queue, payload)` | 进程内缓冲，退出时经认证 stdout 协议交给父进程；payload 约 64KiB 上界——**大内容不进 payload**，放 cache/文件后用指针回源 |

**引擎刻意不提供的能力**（对搭建自己的系统很重要）：没有 HTTP/网络原语（网络 egress 只能以子进程形式发生，如 `exec_sync` + curl）；没有通知/webhook 原语（源码注释明确："human notification, if needed, is represented through existing git/fs/log facts rather than a new SDK function"）；没有 `json.encode`；没有 sleep timer 和动态 SDK 扩展。

边界资源遵循 capability security：引擎能触达的外部资源静态枚举为 `codex.process`、`shell.process`、`argv.process`、`git.process`、`runtime.filesystem`、`wall-clock`——**不存在 network 资源类**。

## 6. 包体系：fkst-packages

### 6.1 包清单（20 个：6 flat + 14 composed）

**Flat 包**（`kind = "package"`，自包含，内部用裸队列名）：

| 包 | persistence_class | 用途 |
|---|---|---|
| `consensus` | judgment_pipeline | 源无关的多角度 codex 共识引擎：消费抽象 `proposal`，产出 `consensus_reached` 或带收窄问题的 `consensus_converge` |
| `github-proxy` | stateless_adapter | **唯一**碰 GitHub API 的地方：入站 poll 差分成事件，出站评论/label/建 issue（默认 dry-run、marker 幂等、限流） |
| `idle-detector` | stateless_adapter | cron 读引擎 observe 事实 + 自认领 open issue 数，系统安静时 fanout 广播 `system_idle` |
| `git-branch-detector` | stateless_adapter | cron 探测声明的 git ref 变更，fanout `git_ref_changed` |
| `github-external-pr-intake` / `github-ratchet-migration-slicer` | — | 第三方 PR 桥接 / ratchet 迁移切片 |

**Composed 包**（`kind = "package.composed"`，组合兄弟包队列，`[event_deps]` 声明依赖使 conformance 可测联合图）：`github-devloop` 家族 8 个包（intake / intake-default / workflow / 本体 / pr / decompose / integration / ops）+ `archaudit` + `autochrono` + `github-autochrono` + `fkst-substrate-ref-maintainer` + `frontend-devloop` + `integration-coverage-producer`。

共享库 5 个（`libraries/`，依赖 DAG 被 conformance 锁定）：`contract`（值/协议原语：source_ref、error_facts、strings）、`workflow`（saga 部门骨架、codex 调用封装、liveness 契约、死信处理）、`forge`（gh/git argv 适配器 + 测试假件，业务层禁止裸拼命令）、`testkit`、`devloop`（devloop 产品内核，约 120 个模块，可见性白名单限定家族使用）。

### 6.2 包的解剖与清单

```text
packages/<name>/
  fkst.toml                     # kind / name / persistence_class / [lib_deps] / [event_deps] / [conformance]
  core.lua                      # 包内共享逻辑（纯函数为主，便于测试）
  departments/<dept>/main.lua   # M.spec + pipeline(event)
  raisers/<r>.lua               # cron / file_watch 声明
  tests/*_test.lua              # 引擎 test runner 执行
  conformance/pack.toml         # （可选）随包旅行的声明式规则包
```

`persistence_class` 是类型化持久性声明，全仓实测四种：`stateless_adapter` / `judgment_pipeline` / `composed_judgment_pipeline` / `saga`（devloop 家族——只有 saga 类派生 `saga_recovery` 能力，才能调用 `once`）。

### 6.3 开发者工作流

```sh
cp .fkst/env.example .fkst/env    # BIN= 指向 fkst-substrate 编译产物（有多级自动解析与兜底 build）
scripts/run.sh test               # 与 CI 相同：self-test → 逐包 conformance + 测试 → composed 联合图 conformance → 覆盖率 ratchet
scripts/run.sh doctor             # 只读宿主预检（git/cargo/codex/gh auth/FKST_* facts）
scripts/run.sh run <pkg> <dept> '{"payload":{}}'   # 单发一个事件跑一个部门，打印 RAISED 结果
scripts/run.sh check              # ~40 个静态守卫（1000 行上限、禁跨包 require、禁裸 gh/git 命令等）
```

引擎侧 gate 是 `fkst-substrate/scripts/verify.sh`（Tier I 行数审计 → cargo build/test → self-test → conformance → 包测试）。conformance 是**不可覆盖 gate**：`runtime-layout`、`project-layout`、`locale-catalogs`、`persistence-class`、`graph-scan`、`department-non-empty`、`schema-validation` + 各包自带规则包。

## 7. 旗舰工作流走读

### 7.1 github-devloop：从 issue 到 PR 合入的自治开发循环

devloop 家族把"issue 提出 → 多角度共识评审 → codex 写代码 → 开 PR → 共识 review → 修复循环 → 确定性合并 → 关 issue"做成一个**可随时 SIGKILL 重启**的状态机。要点：

- **GitHub 就是数据库**：状态 = issue/PR 评论里本 bot 写的 HTML marker（`<!-- fkst:github-devloop:state:v1 ... -->`），读取时只认 `author_login == FKST_GITHUB_BOT_LOGIN` 的评论（普通用户伪造 marker 无效）；label 只是自愈 UI 提示。崩溃恢复 = 再 poll 一次、从 marker 重导状态。
- **事件主干**：`github-proxy` cron 5 分钟 poll → 差分出 `github_entity_changed`（小 payload：repo/number/updated_at + dedup_key + source_ref）→ intake 准入（codex 判 enable/decline）→ `consensus` 多角度并行 codex 盲评（默认 teleology/parsimony/fidelity 等角度，read-only 沙箱）→ 不一致走反驳轮 → 仍不一致 spawn meta-judge 合成收窄问题重新提案 → 达成一致后写 ready marker → **写确认事件回流**（`github_comment_written`）才派生前进事件 → implement 部门在隔离 worktree spawn codex（2h 超时）写代码 → push → PR 侧 review 共识 → fix 循环 → **确定性合并门**（可信 approve marker + head 未变 + CI green，普通 `gh pr merge`，LLM 不摸 merge 按钮）。
- **哪些部门真正用 LLM**：consensus.decide、intake_judge、workflow_select、implement、fix、review_meta、decompose、sync_conflict——其余（observe/loop/reconcile/merge/proxy）全部是**确定性代码**。"判断交给 codex，权力留给确定性代码"。

### 7.2 archaudit：离"监控 → LLM 分析 → 告警"最近的现成样板

`archaudit`（[main.lua](~/Code/fkst-packages/packages/archaudit/departments/audit/main.lua)、[core.lua](~/Code/fkst-packages/packages/archaudit/core.lua)）是"定时/条件触发 → LLM 分析 → 结构化产出 → 对外告警（建 issue）"的完整实现：

1. **双触发**：cron 30 分钟 `archaudit_tick` + 订阅 `idle-detector.system_idle`（系统空闲优先审计；但 24h staleness 到 force-at 点即使不空闲也强制补审）。
2. **durable 时间锚**：用 GitHub 上带 `fkst:archaudit:audit-run:v1` 标记的 issue 作为"上次审计时间"的事实源（不是本地状态），据此判定是否到期。
3. **LLM 分析**：`spawn_codex_sync` 携带严格 prompt——要求只返回 JSON 数组，schema 为 `{"file","line","rule","why","suggested_fix"}`，明确禁止"vague smells / invented rules"。
4. **fail-closed 校验 + 反幻觉核验**：`parse_findings_json` 拒绝一切非严格 JSON 数组，每条 finding 校验字段长度上限，还要用 `git show HEAD:<file>` 验证 file:line 当前真实存在。
5. **有界告警出口**：构造 `github-proxy.issue-create.v1` 请求（内容派生 dedup_key），每轮最多 3 个 issue；零 finding 也发一条"审计完成"issue 作为下一轮时间锚。
6. **活性契约**：`producer_liveness_contracts` 把"最多沉默 30m、最迟 24h 必产出"写成机械可查的契约，由 conformance 强制。

## 8. 设计模式清单（搭建自己系统时可直接照抄）

1. **外部系统即数据库**：跨 pipeline 真相只来自 git/GitHub/host 事实，包内无持久业务态；状态写成认证 marker，读取按作者过滤。
2. **一个 proxy 包做全部 I/O 边界**：入站 poll 差分成小事件，出站全部是请求队列；dry-run 默认（`FKST_GITHUB_WRITE=1` 是唯一真写开关）、写边界 marker 幂等、写确认回流事件、限流错误归类 retryable。
3. **三段式 saga 部门**：`with_lock` 内回源读最新事实做版本 CAS → 锁外跑 codex（预检防 double-spawn）→ 写回前再回源 CAS 一次（codex 跑了两小时，世界可能变了）。
4. **用 `error()` 表达"等一会再试"**：读滞后、rate limit、命令失败都抛带 error-class 前缀的错误，借可靠投递的指数退避重投；耗尽进 DLQ，DLQ 再由 ops 限量升级成工单。
5. **LLM 输出 fail-closed 解析**：哨兵行协议（`⟦FKST:VERDICT⟧` 全文恰好一对且紧邻回复行，封死注入）、严格 JSON schema、长度上限、事实核验；解析失败走确定性 fallback 或直接 block。
6. **payload 小指针化**：大内容（diff、日志段）落 runtime cache/文件，payload 只带 `source_ref`/`content_fetch` 指针 + dedup_key，消费方回源拉取。
7. **同一件事永远只有一个活 codex**：`convergence_identity(role, proposal_id, dedup_key)` + `fkst.codex_runs()` lease 查询，重启后靠同身份收养或重驱。
8. **双网兜底**：错误侧 retry→DLQ→triage；活性侧 cron liveness sweep + observability 部门（reaper、queue-starvation 检测）从事实源 level-triggered 重导——"该发生却没发生"也要有人管。
9. **预算处处有界**：实现尝试次数、converge 轮次、poll 重放预算、WIP 容量、每轮 issue 上限、codex 超时——没有无界循环。
10. **一切可 SIGKILL**：不做优雅关停；恢复 = durable 重投 + marker 重放；所有效果幂等可重入。

---

*配套的审计日志监控方案见 [audit-log-llm-监控告警方案.md](audit-log-llm-监控告警方案.md)。本报告由多智能体深读（5 个并行代码分析 agent 覆盖引擎架构/事件流/SDK/包体系/devloop 走读）+ 人工交叉核验生成。*
