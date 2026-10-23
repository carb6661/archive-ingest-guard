# Archive Ingest Guard

[![Tests](https://github.com/carb6661/archive-ingest-guard/actions/workflows/tests.yml/badge.svg)](https://github.com/carb6661/archive-ingest-guard/actions/workflows/tests.yml)

面向文档导入、RAG 知识包预处理与后台批量上传的**本地 ZIP 隔离接收工具**。使用 Python 标准库，先拒绝不符合约定的路径/成员/预算，再完整读取校验；只有全包通过，才发布到一个全新容器的 `payload/` 目录。

它解决“业务必须接收一个小型文档 ZIP，但不能直接相信包内文件名、声明大小或写入位置”的边界问题。不是杀毒软件、内容净化器、通用解压器，也不是已经部署的上传服务。`verified` 只表示本项目的结构与字节预算校验完成，**不表示文件内容安全、合法或可信**。

## 能做什么

- 严格相对路径：拒绝父目录/绝对路径/盘符/反斜杠、NUL、设备名、NTFS 流分隔符、大小写/目录前缀碰撞等。
- 小型文档配置：仅允许 `.md`、`.txt`、`.json`、`.csv`；只接收 STORED/DEFLATED、非加密 ZIP；拒绝符号链接、设备/FIFO、reparse 属性和异常目录记录。
- 双层资源预算：先检查声明大小、成员数、比例，再对实际读取的字节执行单文件/全包/比例上限；超预算的数据块不写入磁盘。
- 完整读取普通文件并由 `zipfile` 检查其 CRC、局部头等约束；SHA-256 绑定输入快照和成功输出。
- 隔离落盘：独占创建新容器，写入私有 `.pending-*`，全部校验后同容器重命名为 `payload`。不覆盖、不合并已有目标；失败只清理本次新建的容器。
- JSON 证据：规则码、阶段、成员序号、拒绝名称的摘要、静态修复建议；不回显被拒绝的原始名称或底层异常。
- 12 个原创微型合成情境、回滚/故障/边界回归、Windows/Linux CI。

与本作品集中日志阈值、Webhook 幂等、工作流审查和 RAG 对象权限项目不同，这里关注**不可信归档 → 本地文件系统**的应用安全边界。没有增加一个同类扫描器，也没有把本模块冒充完整 RAG 系统。

## 3 分钟运行

需要 Python **3.11–3.13**，含 `zlib`。无需 pip 依赖、API Key、网络服务或管理员权限。以下命令在克隆后的仓库根目录执行，Windows 可将 `python` 换成 `py -3.12`。

```bash
git clone https://github.com/carb6661/archive-ingest-guard.git
cd archive-ingest-guard
python -X utf8 -m unittest discover -s tests -v
python -X utf8 -m archiveguard demo
```

`demo` 在临时工作区内运行微型内存 ZIP，校对 [固定证据](examples/expected.json)，正常结束后自动清理临时演示数据。坏路径只用作元数据输入，**不会运行有漏洞的解压基线，也不会写出到隔离区外**；比例测试最大仅 8 KiB 重复文本，不提供大体积压缩炸弹。

### 创建一个良性知识包并接收

```bash
python examples/make_bundle.py
python -X utf8 -m archiveguard check output/synthetic.zip
python -X utf8 -m archiveguard extract output/synthetic.zip output/quarantine-demo
```

样本全部原创合成，不含正式等保标准、客户记录或真实凭据。成功输出为：

```text
output/quarantine-demo/
└── payload/
    ├── controls/access.md
    └── manifest.json
```

实际样本 ZIP 为 368 字节，解压后 2 个文件、共 132 字节。再次执行样本创建命令不会覆盖已有 ZIP；再次向相同目标解压会返回 `destination_exists`，不是“更新现有目录”。重新演示时请选择新的目标名，不要为此删除现有数据。

## 命令与退出码

```bash
# 完整读取/校验，但不写出成员内容
python -X utf8 -m archiveguard check ./bundle.zip

# 父目录须预先存在且可信；目标容器自身必须不存在
python -X utf8 -m archiveguard extract ./bundle.zip ./quarantine/new-bundle

# 按业务收紧预算；单位是字节而非字符
python -X utf8 -m archiveguard check ./bundle.zip --entries 32 --file-bytes 262144 --total-bytes 1048576 --ratio 50
```

CLI 可设置 `--archive-bytes`、`--entries`、`--file-bytes`、`--total-bytes`、`--ratio`。路径配置保持固定；没有“忽略坏文件继续解压”或跳过 CRC 的开关。

| 退出码 | 语义 | 自动化应做什么 |
| --- | --- | --- |
| 0 | `verified`（仅检查）或 `published`（隔离输出完成） | 仍需执行独立内容审核/解析及授权检查 |
| 2 | 策略/格式/完整性拒绝；也包括 CLI 参数语法错误 | 不自动重试放宽策略，不使用部分输出 |
| 3 | 本地输入/配置/文件系统错误，或清理失败 | 检查工作区/剩余空间/权限，人工确认后以新目标重试 |

合法命令的业务结果输出一个 JSON 文档。`--help` 和参数语法错误由 argparse 输出普通帮助文本，不承诺 JSON。超大输入在 CLI 读快照阶段返回 `input_or_policy_error`/3；直接调用字节 API 时返回 `archive_limit`/2 语义报告。

## 默认接收约定

| 约束 | 默认值 |
| --- | --- |
| ZIP 输入快照 | 2 MiB，代码硬上限 32 MiB |
| 中央目录记录（含显式目录） | 128，配置硬上限 4096 |
| 单文件解压字节 | 4 MiB |
| 全包解压字节 | 16 MiB |
| 单成员解压/压缩比例 | ≤100，分母使用 `max(1, compress_size)` |
| 路径深度/长度/单段长度 | ≤8 段 / 180 字符 / 80 字符 |
| 路径字符 | 段首为 ASCII 字母、数字或 `_`；后续只允许字母、数字、`_`、`-`、`.` |

拒绝段尾点、`.`/`..`、Windows 常见设备名（额外保守拒绝 COM0/LPT0）、前导点/连字符、空格、`~`、`%` 及所有非 ASCII 文件名；保留获准名称，不静默改名修复。**中文正文可正常保存，中文文件名目前不支持**。同名、大小写别名、文件/目录冲突与 `Docs/a.txt` + `docs/b.txt` 的前缀别名均拒绝。显式目录允许在子文件之前或之后出现，但重复显式记录拒绝。

这些是明确的业务取舍，不是断言中文文件名或高压缩率数据本身有害。需要更多格式/命名能力时，应设计新的版本化策略和迁移测试，不能简单删除校验。`.txt` 后缀也可能包裹二进制内容，本项目不做格式识别。

## Python 集成

从本仓库根目录导入，无需额外安装：

```python
from pathlib import Path
from archiveguard import ArchiveGuard, Limits, read_snapshot

limits = Limits(entries=32, total_bytes=1024 * 1024)
snapshot = read_snapshot(Path("output/synthetic.zip"), limits)
guard = ArchiveGuard(limits)

report = guard.extract(snapshot, Path("output/new-private-container"))
if report["outcome"] != "published":
    # 不使用部分输出；不要把拒绝名称或底层路径写进共享日志。
    raise RuntimeError(report["issue"]["code"])

# 只消费 payload/；后续仍需独立的格式校验、内容安全和租户授权。
for member in report["files"]:
    path = Path("output/new-private-container/payload") / member["path"]
    # 在资源受限 worker 中处理 path；不要 eval/exec、运行文件或渲染原始 HTML。
```

`ArchiveGuard.check(bytes)` / `.extract(bytes, destination)` 接收不可变 `bytes`；策略拒绝通过报告返回。调用参数类型不符抛 `TypeError`，非法 Limits 抛 `ValueError`；`read_snapshot` 的本地 I/O/大小问题也由调用者处理。输入/工作区必须由可信本地调用方控制，不能存在恶意并发替换。

### 接入 RAG 系统时的分层

```text
认证/租户配额 → 有界上传快照 → 本模块结构/流式隔离
             → 独立格式与内容校验 → 文档切分/来源绑定 → 授权索引/检索
```

本仓库只实现中间的 ZIP 接收层。租户身份、目的目录、标准名称/级别/版本不能从 ZIP 自报字段直接信任。可与 [Compliance RAG Assistant](https://github.com/carb6661/compliance-rag-assistant) 的解析能力组合，但目前**没有跨仓库集成测试、HTTP 上传路由或自动入库**。

## 如何读证据

成功报告包含 `archive_sha256`、实际字节数，以及每个普通文件的中央目录 `index`、获准路径、实际大小和 SHA-256。拒绝报告的 `files=[]`、`observed_bytes=null`，不把部分校验结果当成功。`member_index` 从 0 开始；`name_sha256` 是被拒绝名称的精确摘要，供本地授权排查，不是认证或匿名化保证。

常见拒绝码：

| 代码 | 问题 | 推荐操作 |
| --- | --- | --- |
| `path_policy` / `namespace_collision` | 路径不符合策略、命名空间冲突 | 联系提供者按规则重命名后重新打包，不自动删 `../` |
| `member_type` / `method_policy` | 链接/设备/加密/不支持方法 | 用可信工具导出普通非加密文档包 |
| `file_limit` / `total_limit` / `ratio_limit` / `entry_limit` | 声明或实际资源预算超限 | 拆包并核对业务必要性，不自动上调限制 |
| `invalid_archive` / `invalid_member` / `size_mismatch` | 结构、CRC、局部头或实际大小问题 | 重新导出，绝不跳过完整性检查 |
| `destination_exists` | 目标已存在 | 新建任务 ID，保留原内容 |
| `cleanup_failed` | 失败后清理未完成 | 返回 error；隔离目录可能残留，只允许人工授权检查 |

报告中获准的名称与文件摘要也可能属于业务数据，生产环境应私有存储并设置保留期。不要把客户压缩包/导出报告提交到公开仓库。

## 问题、技术决策与验证

见 [技术深挖：问题 → 方案 → 证据 → 剩余风险](docs/TECHNICAL_DEEP_DIVE.md)、[威胁模型](docs/THREAT_MODEL.md)、[接收与失败处置手册](docs/OPERATIONS.md)、[实际验证记录](docs/VALIDATION.md)。

测试包含路径与前缀碰撞、NUL 原名、模式类型、实际流限额、CRC 后置失败、目标独占竞争、发布/清理失败、原有内容保留、CLI 退出码、真实文件输出与固定情境重放。数量及平台跳过情况以验证记录和 CI 日志为准，不将注入测试等同真实内核攻防。

## 必须知道的局限

1. **不判定内容安全。** 假扮 `.txt` 的 ZIP、恶意 Markdown/HTML、CSV 公式、提示词注入、隐私数据仍可能获准隔离；有测试专门保留这一反例。不会联网、执行或递归解包，不自动送入模型。
2. **不是强资源沙箱。** `zipfile` 在成员数检查前已解析中央目录；输入字节上限减少风险，但不能提供硬 CPU/内存/墙钟时限。比例分母来自不可信元数据，绝对字节预算是另一个独立约束；解析器及解压器内部也会分配内存。
3. **不抵抗恶意本地并发写入。** 检查父目录 link/reparse 不等于消除 TOCTOU。只用于可信私有本地工作区；没有 dirfd/内核强制隔离或 Windows ACL 管理，不支持网络共享保证。
4. **不保证崩溃持久事务。** 捕获到的失败会尽力清理；断电/强杀可能留下 `.pending-*`，重命名后也可能在报告送达前退出。`payload` 重命名不等于 fsync 持久提交，不自动重试覆盖旧容器。
5. **不是 ZIP 规范证明器。** 依赖维护中的 Python `zipfile` 对实际暴露流的校验；不认证归档来源、所有附加/尾随字节或下游解释器。SHA/CRC 都不是恶意内容判定。

生产接入前至少补 worker 进程/容器配额、任务/用户总量限制、可信身份与对象权限、Windows 私有 ACL、格式校验、敏感数据/内容策略、崩溃恢复及受控审计。本仓库不宣称生产就绪、真实客户案例或攻击覆盖率。

## 项目结构

```text
archiveguard/
  core.py          策略、路径命名空间、流式预算、隔离发布
  __main__.py      check / extract / demo CLI
  demo.py          原创微型样本和固定情境断言
examples/
  make_bundle.py   良性样本生成（拒绝覆盖）
  expected.json    12 情境预期摘要；不含主机路径
tests/
  test_archiveguard.py
docs/
  THREAT_MODEL.md
  TECHNICAL_DEEP_DIVE.md
  OPERATIONS.md
  VALIDATION.md
.github/workflows/tests.yml
```

## 学习与求职展示

适合 AppSec/安全开发/DevSecOps 岗位讨论不可信路径、跨平台文件名、声明与观测量差异、最小权限、私有暂存/发布边界、失败语义、证据最小化和回归方法。可以演示“先发现业务边界，再用实际失败用例驱动修正”，不把作品集工具描述成商用网关或真实应急经历。

## 设计参考

- [Python zipfile 官方文档](https://docs.python.org/3.11/library/zipfile.html#decompression-pitfalls)：CRC/格式错误、文件系统/资源限制、中断与覆盖行为等风险背景；本项目在其之上增加独立的接收约定。
- [OWASP 文件上传防护](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)：分层限制、隔离存储及解压后配额背景；本工具仅实现其中的局部控制，不宣称符合整个指南。
- [Microsoft 文件命名规则](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file)：保留字符、设备名、大小写与别名差异；本项目故意选择更窄的 ASCII 策略。

MIT License。仅用于合法防御和授权本地实验；反馈 Bug 时请使用微型合成样本，勿公开真实凭据/业务压缩包。
