# secret

本项目是一个基于 Python 的模拟邮件发送客户端，使用 RSA 签名和随机 AES
算法加密数据，确保邮件的安全性。该工具适用于对数据安全和加密通信有较高要求的场景，如安全通信测试、加密邮件发送等。

## 功能介绍

- **RSA 签名**：对邮件内容进行 RSA 签名，确保邮件内容的完整性和真实性。
- **AES 加密**：使用随机 AES 算法加密邮件内容，确保邮件内容的机密性。
- **模拟邮件发送**：通过 SMTP 协议发送加密和签名的邮件。
- **邮件接收和解密**：接收加密邮件，并使用 RSA 和 AES 进行解密和验证签名。

## 环境配置

### 前提条件

请确保您的系统中已安装以下软件：

- Python 3.11+
- MySQL 数据库

### 安装步骤

1. 克隆项目到本地：
    ```bash
    git clone https://github.com/qtgolang/SunnyNetTools.git
    cd SunnyNetTools
    ```

2. 创建并激活虚拟环境：
    ```bash
    conda create -n rsa python=3.11.9
    conda activate rsa
    ```

3. 安装所需的 Python 包：
    ```bash
    pip install -r requirements.txt
    ```

4. 配置数据库连接信息：
   编辑 `database.py` 文件，修改数据库连接字符串为您的 MySQL 数据库信息：
    ```python
    DATABASE_URL = "mysql+pymysql://root:your_password@localhost/your_database"
    ```

## 使用方法

### 发送端

1. 启动发送端：
    ```bash
    python sender.py
    ```

2. 在发送端界面中，输入接收者的邮箱地址和邮件内容，点击发送按钮。

### 接收端

1. 启动接收端：
    ```bash
    python receiver.py
    ```

2. 在接收端界面中，点击接收邮件按钮，然后点击解密按钮查看解密后的邮件内容。

## 联系方式

如需有偿解决问题或提供其他帮助，请联系：

- QQ: 284190056
- 微信: AirEliauk9527
