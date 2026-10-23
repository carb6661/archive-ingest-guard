# 实际验证记录

核验日期：2026-10-23。以下仅为本仓库合成实验，不是生产部署、真实事件或形式化验证。

## 本地执行

Windows / Python **3.12.8**，仓库根目录：

```bash
python -S -X utf8 -m unittest discover -s tests -q
python -S -X utf8 -m archiveguard demo
python examples/make_bundle.py
python -X utf8 -m archiveguard check output/synthetic.zip
python -X utf8 -m archiveguard extract output/synthetic.zip output/quarantine-demo
```

最终 unittest 注册 **106 项，105 项通过、1 项跳过、0 失败/错误**。跳过项为真实目录符号链接创建：本机用户/OS 不允许该操作；不是被记为通过。reparse 属性判定、父路径拒绝和输入 link 拒绝的注入分支仍正常执行。测试包含动态注册的 25 个独立坏路径项；不把每一个 subTest 再额外统计成项目数。

`-S` 禁用 site 初始化，代码及测试无需安装第三方依赖。CLI 子进程也使用 -S。此项不保证解释器/OS 本身没有漏洞。

良性示例实际输入 368 字节，SHA-256：

```text
667dcb35a91af0b5931306c1ef9649774cb087a3b3d49d3ca4a05ace4d4f15cb
```

check 返回 verified，extract 返回 published；两份输出分别 84、48 字节，总计132。文件内容摘要与报告对应，目标仅留下 payload；无真实业务或第三方标准全文。

## 12 情境重放

[expected.json](../examples/expected.json) 是合成情境摘要，demo 必须与其一致。它不包含临时绝对路径、时间或不稳定的压缩实现摘要；成功内容摘要固定。没有执行危险的“修复前解压器”。before/after 指输入包显式修复，策略保持不变。

| 情境 | 实际结果 | 落盘 |
| --- | --- | --- |
| before-parent-path | metadata / path_policy | 无目标 |
| after-clean-bundle | published，2文件，132字节 | 仅新容器/payload |
| case-alias | namespace_collision | 无目标 |
| prefix-alias | namespace_collision | 无目标 |
| symlink-metadata | member_type | 无目标 |
| unsupported-extension | extension_policy | 无目标 |
| file-budget | file_limit | 无目标 |
| total-budget | total_limit | 无目标 |
| entry-budget | entry_limit | 无目标 |
| ratio-budget（8 KiB） | ratio_limit | 无目标 |
| corrupt-stream | stream / invalid_member | 失败后新容器被清理 |
| existing-container | destination / destination_exists | 原有 marker 保持不变 |

这是固定小样本，不是攻击覆盖率、误报率或真实压缩炸弹承载测试。

## 单元与集成证据

- 原名 NUL/平台分隔符、路径长度/深度/设备名、大小写及前缀两向冲突。
- 目录前后顺序、重复记录、非普通类型、加密标记、未知压缩方法、后缀白名单。
- 声明大小拦截、实际 file/total/ratio 限额、EOF/长度不符、64KiB读取、CRC/局部头差异。
- 后续成员坏 CRC 时首成员也不发布；已有目录/文件保留；独占保留前注入竞争，不删除其他所有者创建的 marker。
- 在真实 rename 前观察所有文件已齐备且 payload 不存在；发布/暂存故障清理；清理失败明确 error 并允许残留，而非声称回滚成功。
- CLI 成功/拒绝/本地输入/参数限制、输出摘要不回显拒绝名；真实文件/哈希核验。
- 专门保留 `.txt` 实际为 ZIP 字节但仍 verified 的案例：内容识别不是已实现的功能。

故障/假流/reparse注入用于确定性验证分支，不等于真实磁盘耗尽、恶意内核竞争或生产故障测试。没有宣称并发吞吐、峰值内存、检出率或生产SLA。

## 发布前检查

使用现有 Local Secret Scanner 对本项目目录运行 `--fail-on-findings`，本次为 **0 条规则匹配**；人工检查拟发布文件仅含原创代码/文档/微型合成数据，没有 `.env`、ZIP 原件、客户名称、私有绝对路径或真实凭据。规则扫描与人工复核都不等于绝对无秘密证明。

使用 Workflow Trust Auditor 审查自身 CI：**0 条静态子集规则匹配**。工作流显式 contents:read、禁用持久 checkout 凭据、直接 actions 固定提交；这不验证传递依赖/runner 或远端 action 源码。

## CI

[首次发布 CI](https://github.com/carb6661/archive-ingest-guard/actions/runs/39974907963) 对应代码提交 `eea141bfc001d0afc0ff57cf49c82cfb2ea9b559`，Windows/Linux × Python3.11/3.12/3.13 **六组全部成功**。逐组日志均为 `Ran 106 tests` / `OK`，没有跳过；12情境demo也均完成。

CI runner 允许创建目录符号链接，真实父目录 symlink 拒绝测试在六组都实际执行通过。不能反过来把本机因权限跳过的项目说成本机通过，也不能把 CI 的 symlink 用例当作全部 Windows reparse 类型或恶意竞态均已覆盖。
