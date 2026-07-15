# AGENTS.md

## 关联 fkst 仓库

本项目依赖同一开发环境中的其他 fkst 仓库：

- `fkst-substrate` 位于 `~/Code/fkst-substrate`。
- `fkst-packages` 位于 `~/Code/fkst-packages`。

这两个仓库仅作为只读的依赖源码参考。除下述清理和同步操作外，禁止在其中实现功能、编辑或新增文件、提交、推送、切换分支，任务产生的代码改动只能发生在本仓库。

## 任务开始前的同步检查

每次执行任务前，必须主动把上述两个仓库的当前分支同步到各自 upstream 的最新状态：

1. 使用 `git fetch --prune` 刷新远端引用，并检查工作区、当前分支、upstream 和 ahead/behind 状态。
2. 这些依赖仓库不保留任何本地改动。若存在 staged、unstaged 或 untracked 改动，直接回滚已跟踪文件并删除未跟踪文件；不得 stash、提交或推送这些改动。
3. 当前分支仅落后 upstream 时，使用 `git pull --ff-only` 更新；当前分支 ahead 或已分叉时，直接将当前分支和工作区重置到 upstream，再清理未跟踪文件，确保最终 ahead/behind 为 `0/0` 且工作区干净。
4. 依赖仓库未同步或存在本地改动不得成为暂停本仓库任务的理由。应先按上述规则自行清理并同步，然后继续本仓库任务，不得仅报告状态后停下。

若仓库不存在、没有 upstream、网络不可用或因外部原因确实无法同步，说明实际状态和未验证范围，但继续推进本仓库中不依赖该缺失信息的工作；不得对未验证的依赖行为作确定性结论。

涉及 fkst 引擎或官方 package 行为时，以同步后的 `fkst-substrate` 和 `fkst-packages` 源码为准，不依赖旧构建产物、缓存或过期文档作结论。

## 指令文件

`AGENTS.md` 是本仓库 agent 指令的唯一维护源。`CLAUDE.md` 必须保持为指向 `AGENTS.md` 的相对软链接，不得单独维护或复制内容。
