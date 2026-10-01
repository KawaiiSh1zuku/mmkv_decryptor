# mmkv_decryptor - RadiumWMPF MMKV 解密工具

该工具读取本地 RadiumWMPF MMKV 存储，完成 AES-CFB 解密、MMKV 追加记录解析，并可将结果导出为高保真 JSONL 镜像。

**数据安全声明：导出的 JSON、JSONL 和终端输出可能包含令牌、用户标识及其他敏感数据！**

## 环境

```powershell
pip install -r requirements.txt
```

## 存储标识

`--store-id` 是 MMKV 数据文件名，也是 RadiumWMPF 密钥派生所需的标识。一般对应 `%USERDATA%\AppData\Roaming\Tencent\xwechat\radium\users\<user_id>\applet\local` 中的小程序 id。

## 定位与解密

```powershell
python main.py locate --store-id wxaaaaaaaaaaaaaaaa

python main.py dump `
  --store-id wxaaaaaaaaaaaaaaaa `
  --app-dir C:\path\to\local\target-directory
```

`dump` 返回全部解析键值、数据类型、原始值长度和来源文件。

## 导出 JSONL 镜像

```powershell
python main.py export-jsonl `
  --store-id wxaaaaaaaaaaaaaaaa `
  --app-dir C:\path\to\local\target-directory
```

未指定 `--output` 时，输出到当前工作目录下的 `<store-id>.jsonl`。可用 `--output analysis.jsonl` 指定其他路径。已有输出文件默认不会被覆盖；需要替换时显式传入 `--overwrite`。

JSONL 按以下顺序写入：

- `manifest`：镜像 schema、存储标识和记录数量。
- `source`：数据文件、`.crc` 文件、CRC、version、sequence、IV、actual size 和记录区偏移。
- `record`：每条追加记录的 key、精确偏移、删除状态、最终有效状态、完整原始记录及 raw value。
- `current`：最终有效 key 到原始记录的引用。

二进制字段使用 Base64。`raw_record_base64` 配合 `source.plaintext_prefix_base64` 可以重建解密后的记录流；`decoded_value` 仅作为便于分析的业务层解释，不替代原始字节。

## Python API

```python
from pathlib import Path

from wechat_mmkv import dump_storage, export_jsonl, extract_session

storage = dump_storage(
    "lab-analysis-store",
    app_dir=Path(r"C:\path\to\local\target-directory"),
)
export_jsonl(storage, Path("analysis.jsonl"))
```
