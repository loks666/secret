# sender.py
import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QStackedWidget, QHBoxLayout, QSpacerItem, QSizePolicy
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64encode
import smtplib
from email.mime.text import MIMEText
from database import SessionLocal, get_user_by_username, create_user, create_info, get_user_by_email


class RegisterLoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.session = SessionLocal()

    def init_ui(self):
        self.setWindowTitle('注册 & 登录')
        self.setGeometry(100, 100, 600, 400)

        self.stacked_widget = QStackedWidget(self)
        self.login_widget = QWidget()
        self.register_widget = QWidget()

        # 设置全局字体
        font = QFont('微软雅黑', 10)
        self.setFont(font)

        # 登录界面
        login_layout = QVBoxLayout()

        self.login_username_input = QLineEdit(self.login_widget)
        self.login_username_input.setPlaceholderText('用户名')
        login_layout.addWidget(self.login_username_input, alignment=Qt.AlignCenter)

        self.login_password_input = QLineEdit(self.login_widget)
        self.login_password_input.setPlaceholderText('密码')
        self.login_password_input.setEchoMode(QLineEdit.Password)
        login_layout.addWidget(self.login_password_input, alignment=Qt.AlignCenter)

        self.login_button = QPushButton('登录', self.login_widget)
        self.login_button.clicked.connect(self.login)
        login_layout.addWidget(self.login_button, alignment=Qt.AlignCenter)

        self.to_register_button = QPushButton('没有账户？注册', self.login_widget)
        self.to_register_button.clicked.connect(self.show_register)
        login_layout.addWidget(self.to_register_button, alignment=Qt.AlignCenter)

        self.login_message_label = QLabel(self.login_widget)
        login_layout.addWidget(self.login_message_label, alignment=Qt.AlignCenter)

        login_layout.setAlignment(Qt.AlignCenter)
        login_layout.setSpacing(10)
        self.login_widget.setLayout(login_layout)

        # 注册界面
        register_layout = QVBoxLayout()

        self.register_username_input = QLineEdit(self.register_widget)
        self.register_username_input.setPlaceholderText('用户名')
        register_layout.addWidget(self.register_username_input, alignment=Qt.AlignCenter)

        self.register_password_input = QLineEdit(self.register_widget)
        self.register_password_input.setPlaceholderText('密码')
        self.register_password_input.setEchoMode(QLineEdit.Password)
        register_layout.addWidget(self.register_password_input, alignment=Qt.AlignCenter)

        self.register_email_input = QLineEdit(self.register_widget)
        self.register_email_input.setPlaceholderText('邮箱')
        register_layout.addWidget(self.register_email_input, alignment=Qt.AlignCenter)

        self.register_button = QPushButton('注册', self.register_widget)
        self.register_button.clicked.connect(self.register)
        register_layout.addWidget(self.register_button, alignment=Qt.AlignCenter)

        self.to_login_button = QPushButton('已有账户？登录', self.register_widget)
        self.to_login_button.clicked.connect(self.show_login)
        register_layout.addWidget(self.to_login_button, alignment=Qt.AlignCenter)

        self.register_message_label = QLabel(self.register_widget)
        register_layout.addWidget(self.register_message_label, alignment=Qt.AlignCenter)

        register_layout.setAlignment(Qt.AlignCenter)
        register_layout.setSpacing(10)
        self.register_widget.setLayout(register_layout)

        self.stacked_widget.addWidget(self.login_widget)
        self.stacked_widget.addWidget(self.register_widget)
        self.stacked_widget.setCurrentWidget(self.login_widget)

        main_layout = QVBoxLayout(self)
        main_layout.addWidget(self.stacked_widget)
        self.setLayout(main_layout)

        # 设置按钮样式
        self.set_button_styles()

    def set_button_styles(self):
        # 原来的 login_button_style 现在是蓝色
        login_button_style = """
        QPushButton {
            background-color: #007BFF;
            color: white;
            border-radius: 5px;
            padding: 5px;
            min-width: 100px;
            max-width: 150px;
        }
        QPushButton:hover {
            background-color: #0056b3;
        }
        """

        # 原来的 to_register_button_style 现在是绿色
        to_register_button_style = """
        QPushButton {
            background-color: #28a745;
            color: white;
            border-radius: 5px;
            padding: 5px;
            min-width: 100px;
            max-width: 150px;
        }
        QPushButton:hover {
            background-color: #218838;
        }
        """

        # 原来的 register_button_style 现在是蓝色
        register_button_style = """
        QPushButton {
            background-color: #007BFF;
            color: white;
            border-radius: 5px;
            padding: 5px;
            min-width: 100px;
            max-width: 150px;
        }
        QPushButton:hover {
            background-color: #0056b3;
        }
        """

        # 原来的 to_login_button_style 现在是绿色
        to_login_button_style = """
        QPushButton {
            background-color: #28a745;
            color: white;
            border-radius: 5px;
            padding: 5px;
            min-width: 100px;
            max-width: 150px;
        }
        QPushButton:hover {
            background-color: #218838;
        }
        """

        self.login_button.setStyleSheet(login_button_style)
        self.to_register_button.setStyleSheet(to_register_button_style)
        self.register_button.setStyleSheet(register_button_style)
        self.to_login_button.setStyleSheet(to_login_button_style)

    def show_login(self):
        self.stacked_widget.setCurrentWidget(self.login_widget)
        self.register_message_label.setText('')

    def show_register(self):
        self.stacked_widget.setCurrentWidget(self.register_widget)
        self.login_message_label.setText('')

    def register(self):
        username = self.register_username_input.text()
        password = self.register_password_input.text()
        email = self.register_email_input.text()

        if not username or not password or not email:
            self.register_message_label.setText('所有字段都是必填的')
            return

        if get_user_by_username(self.session, username):
            self.register_message_label.setText('用户名已存在')
            return

        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()

        keys_dir = os.path.join(os.getcwd(), 'keys')
        if not os.path.exists(keys_dir):
            os.makedirs(keys_dir)

        with open(os.path.join(keys_dir, f'{username}_private.pem'), 'wb') as f:
            f.write(private_key)
        with open(os.path.join(keys_dir, f'{username}_public.pem'), 'wb') as f:
            f.write(public_key)

        create_user(self.session, username, password, email, public_key.decode('utf-8'))
        self.register_message_label.setText('注册成功，请登录')
        self.show_login()

    def login(self):
        username = self.login_username_input.text()
        password = self.login_password_input.text()

        user = get_user_by_username(self.session, username)
        if user and user.password == password:
            self.login_message_label.setText('登录成功')
            self.hide()
            self.send_email_window = SendEmailWindow(username)
            self.send_email_window.show()
        else:
            self.login_message_label.setText('用户名或密码错误')


class SendEmailWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.init_ui()
        self.session = SessionLocal()
        self.current_user = get_user_by_username(self.session, username)

    def init_ui(self):
        self.setWindowTitle('发送邮件')
        self.setGeometry(100, 100, 800, 600)

        layout = QVBoxLayout()

        self.recipient_email_input = QLineEdit(self)
        self.recipient_email_input.setPlaceholderText('收件人邮箱')
        layout.addWidget(self.recipient_email_input, alignment=Qt.AlignCenter)

        self.email_content_input = QTextEdit(self)
        self.email_content_input.setPlaceholderText('邮件内容')
        layout.addWidget(self.email_content_input)

        self.encrypted_content_display = QTextEdit(self)
        self.encrypted_content_display.setReadOnly(True)
        layout.addWidget(self.encrypted_content_display)

        button_layout = QHBoxLayout()
        self.encrypt_button = QPushButton('加密和签名', self)
        self.encrypt_button.clicked.connect(self.encrypt_and_sign)
        button_layout.addWidget(self.encrypt_button)

        self.send_button = QPushButton('发送邮件', self)
        self.send_button.clicked.connect(self.send_email)
        button_layout.addWidget(self.send_button)

        layout.addLayout(button_layout)

        self.message_label = QLabel(self)
        layout.addWidget(self.message_label, alignment=Qt.AlignCenter)

        self.setLayout(layout)

        # 设置全局字体
        font = QFont('微软雅黑', 10)
        self.setFont(font)

        # 设置按钮样式
        self.set_button_styles()

    def set_button_styles(self):
        encrypt_button_style = """
        QPushButton {
            background-color: #28a745;
            color: white;
            border-radius: 5px;
            padding: 5px;
            min-width: 100px;
            max-width: 150px;
        }
        QPushButton:hover {
            background-color: #218838;
        }
        """

        send_button_style = """
        QPushButton {
            background-color: #007BFF;
            color: white;
            border-radius: 5px;
            padding: 5px;
            min-width: 100px;
            max-width: 150px;
        }
        QPushButton:hover {
            background-color: #0056b3;
        }
        """

        self.encrypt_button.setStyleSheet(encrypt_button_style)
        self.send_button.setStyleSheet(send_button_style)

    def encrypt_and_sign(self):
        recipient_email = self.recipient_email_input.text()
        email_content = self.email_content_input.toPlainText()

        if not recipient_email or not email_content:
            self.message_label.setText('所有字段都是必填的')
            return

        # 加载用户的私钥
        private_key_path = os.path.join(os.getcwd(), 'keys', f'{self.current_user.username}_private.pem')
        with open(private_key_path, 'rb') as f:
            private_key = RSA.import_key(f.read())

        # 使用私钥对邮件内容进行签名
        h = SHA256.new(email_content.encode('utf-8'))
        signature = pkcs1_15.new(private_key).sign(h)

        # 使用AES加密邮件内容
        aes_key = AES.get_random_bytes(32)
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(email_content.encode('utf-8') + signature)

        # 加载收件人的公钥
        recipient_user = get_user_by_email(self.session, recipient_email)
        if not recipient_user:
            self.message_label.setText('收件人不存在')
            return

        recipient_public_key = RSA.import_key(recipient_user.public_key.encode('utf-8'))

        # 使用收件人的公钥加密AES密钥
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        encrypted_aes_key = cipher_rsa.encrypt(aes_key)

        # 显示加密后的内容
        encrypted_content = b64encode(encrypted_aes_key + cipher_aes.nonce + tag + ciphertext).decode('utf-8')
        self.encrypted_content_display.setPlainText(encrypted_content)

        # 存储公钥信息
        create_info(self.session, self.current_user.public_key, recipient_user.public_key)

        self.message_label.setText('加密和签名成功')

    def send_email(self):
        recipient_email = self.recipient_email_input.text()
        encrypted_content = self.encrypted_content_display.toPlainText()

        if not recipient_email or not encrypted_content:
            self.message_label.setText('所有字段都是必填的')
            return

        # 准备邮件
        msg = MIMEText(encrypted_content)
        msg['Subject'] = '加密邮件'
        msg['From'] = '3435519773@qq.com'
        msg['To'] = recipient_email

        # 发送邮件
        try:
            server = smtplib.SMTP_SSL('smtp.qq.com', 465)
            server.login('3435519773@qq.com', 'eqpnnzxkghufcjei')
            print("发送邮件地址为： " + recipient_email)
            server.sendmail('3435519773@qq.com', recipient_email, msg.as_string())
            server.quit()
            self.message_label.setText('邮件发送成功')
        except Exception as e:
            self.message_label.setText(f'邮件发送失败: {e}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = RegisterLoginWindow()
    window.show()
    sys.exit(app.exec_())
