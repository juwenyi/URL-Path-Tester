# URL Path Tester

一个轻量级的可视化请求测试工具，使用 Python + Tkinter 构建。  
它允许你输入基础 URL 与多行路径（path），程序自动拼接并请求，  
实时显示返回状态码、耗时、响应长度、关键字匹配结果。  

同时支持：
- 自定义请求方法（GET / POST / PUT / DELETE 等）
- 自定义请求头（User-Agent / Cookie / Authorization）
- 请求体（body）设置与 Repeater 模拟
- 关键字高亮与标色匹配
- 并发或顺序请求模式
- 响应详情查看与 CSV 导出
- 可直接打包为 Windows `.exe` 可执行程序

---

## 🧩 功能特性

| 功能 | 描述 |
|------|------|
| **多路径测试** | 每行一个 path，自动拼接基础 URL 并发起请求 |
| **请求方法** | 支持 GET / POST / PUT / DELETE / PATCH 等 |
| **请求头设置** | 可填写 User-Agent / Cookie / Authorization |
| **请求体输入** | 支持 JSON 或任意文本体 |
| **Repeater 模式** | 可粘贴完整 Burp Raw Request，解析 Method、URL、Headers、Body |
| **关键字检测** | 检测响应中包含 success、flag、token 等词时标蓝显示 |
| **筛选排序** | 表格支持按列排序、状态筛选 |
| **响应详情** | 双击某行可查看响应头与响应体完整内容 |
| **CSV 导出** | 一键导出所有请求结果到 CSV 文件 |
| **并发请求** | 用户可定义并发线程数，支持暂停/继续/停止 |
| **顺序请求** | 按行逐个请求，适合低频测试或调试 |

---

## 🚀 使用方法

### 1. 安装依赖

确保系统已安装 Python（推荐 3.8 及以上），然后在命令行中运行：

```bash
pip install requests
