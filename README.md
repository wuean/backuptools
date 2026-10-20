# BackupTool —— 工程文件自动备份工具

面向造价 / 广联达 GTJ 工程文件的轻量自动备份工具。系统自带 ZIP 压缩，无需安装 WinRAR 等外部工具。

- 作者：乐福学长
- 网站：https://lefuo.com

## 功能

- 选择源目录 / 备份目录
- 文件类型过滤（默认 `*.GTJ`，留空 = 全部）
- 双重保留策略：保留天数 + 最多条数（默认 30 天 / 10 条，可设置）
- 开机自动备份、每日定时备份（Windows 任务计划程序）
- 备份进度实时显示 + 完成 / 失败弹窗提醒
- 备份后自动校验包结构、大小与密码
- 压缩包密码保护（传统 ZipCrypto，Windows 资源管理器可直接打开）
- 运行日志 `backup_log.txt`（超 1MB 自动轮转）

## 使用

- 双击 `BackupTool.exe` 打开图形界面
- `BackupTool.exe --silent` 无人值守执行备份（供任务计划程序调用；使用默认密码）

## 从源码打包

```bash
pyinstaller --onefile --noconsole --name BackupTool backup_tool_new.py
```

## 配置

配置文件 `backup_config.json` 位于程序同目录，首次保存后生成。密码不落盘：界面输入不保存，留空时使用默认密码。
