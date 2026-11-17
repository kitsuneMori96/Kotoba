# ruri-no-kasane-zh

「琉璃交错 ～妹物语～」（ルリのかさね ～いもうと物語り～）的简体中文汉化工程。

本仓库只包含汉化所需的引擎补丁源码、离线脚本工具和本地打包／安装器。游戏本体、剧本、译文、图片、摘要清单与补丁产物一律留在本地，不进入仓库。

翻译器不在本仓库开发；早期基于 Node 的审校原型已归档到 `legacy` 分支。

## 结构

- `engine/majiro-win32/`：代理 `winmm.dll` 的 Majiro 引擎汉化层（GDI 文本绘制、内置菜单、字体、人名框、MCI 转发等），使用 MinGW 交叉编译为 32 位 DLL。
- `tools/majiro/`：Majiro ARC V3 与 MJO 的只读审计、文本导出／回写、来源校验和私有补丁包构建工具，纯 Python 标准库。
- `tools/patch-installer/`：单文件自解压安装器。`pack` 把补丁文件与清单追加到 `stub` 之后，安装时校验游戏 exe 与文件摘要，写入前备份到 `.ruri-backup`，支持 `--check`、`--rollback`。
- `work/`、`export/`：本地测试副本、游戏资源与私有产物，已忽略，不提交。

## 引擎补丁

```sh
# 在 WSL 中交叉编译 32 位 winmm.dll
engine/majiro-win32/build.sh
```

运行时环境变量（可选）：

- `RURI_FONT`：替换正文字体（默认 DengXian）。
- `RURI_TRACE`：输出 `ruri_hook.log` 调试日志。

## 安装器

需要 `RURI_PRISTINE` 指向未修改的游戏目录（含原始 exe 与官方 `update.arc`、`fastdata.arc`），安装器图标在构建时从游戏 exe 中提取：

```sh
RURI_PRISTINE=/d/games/ruri \
  tools/patch-installer/build.sh 1.0.0
# 产物：work/installer-build/RuriPatch-1.0.0.exe
```

把生成的 exe 放到游戏根目录运行；参数：

- `--check`：只校验并列出将写入的文件，不做修改。
- `--dir <目录>`：指定游戏目录（默认为安装器所在目录）。
- `--rollback`：按备份撤销补丁。
- `--yes`：跳过确认。

安装状态与备份保存在游戏目录下的 `.ruri-backup/`；旧版安装器留下的 `.kotoba-backup/` 仍会被识别并沿用。

## 工具链

`tools/majiro` 需要本地 MajiroTools 构建产物与私有的游戏数据，命令自带 `--help`：

```sh
PYTHONPATH=. python3 -m tools.majiro --help
```

所有输入输出路径均需本地存在；工具不会下载或上传任何数据。`audit` 为只读检查，未列入白名单的差异会以退出码 2 阻断自动覆盖。

## 许可

引擎补丁与工具源码为本地汉化用途；内置或依赖的第三方组件（MajiroTools 等）保留其原始许可与作者声明。
