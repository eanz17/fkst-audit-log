# AGENTS.md

## 关联 fkst 仓库

本项目依赖同一开发环境中的其他 fkst 仓库：

- `fkst-substrate` 位于 `~/Code/fkst-substrate`。
- `fkst-packages` 位于 `~/Code/fkst-packages`。

## 任务开始前的同步检查

每次执行任务前，必须先确认上述两个仓库的当前分支与各自 upstream 保持最新：刷新远端引用，检查工作区和分支的 ahead/behind 状态，并在工作区干净且可以安全快进时使用 `git pull --ff-only` 更新。

不得用 force pull、reset、checkout 或自动 stash 覆盖这些仓库中的本地改动。若仓库不存在、没有 upstream、工作区有改动、分支已分叉、网络不可用，或因其他原因无法确认已是最新代码，必须先向用户说明实际状态，不得基于可能过期的代码继续判断或实现。

涉及 fkst 引擎或官方 package 行为时，以同步后的 `fkst-substrate` 和 `fkst-packages` 源码为准，不依赖旧构建产物、缓存或过期文档作结论。

## 指令文件

`AGENTS.md` 是本仓库 agent 指令的唯一维护源。`CLAUDE.md` 必须保持为指向 `AGENTS.md` 的相对软链接，不得单独维护或复制内容。
