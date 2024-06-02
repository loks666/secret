# receiver.py
import sys
import os
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLineEdit, QPushButton, QTextEdit, QLabel, QStackedWidget, QHBoxLayout
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from base64 import b64decode
import imaplib
import email
from database import SessionLocal, get_user_by_username, create_user, get_user_by_email

class RegisterLoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.session = SessionLocal()

    def init_ui(self):
        self.setWindowTitle('注册 & 登录')
        self.setGeometry(100, 100, 600, 400)

        # 设置全局字体
        font = QFont('微软雅黑', 10)
        self.setFont(font)

        self.stacked_widget = QStackedWidget(self)
        self.login_widget = QWidget()
        self.register_widget = QWidget()

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
        login_button_style = """
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

        to_register_button_style = """
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

        register_button_style = """
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

        to_login_button_style = """
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
            self.receive_email_window = ReceiveEmailWindow(username)
            self.receive_email_window.show()
        else:
            self.login_message_label.setText('用户名或密码错误')


class ReceiveEmailWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.username = username
        self.init_ui()
        self.session = SessionLocal()
        self.current_user = get_user_by_username(self.session, username)

    def init_ui(self):
        self.setWindowTitle('接收邮件')
        self.setGeometry(100, 100, 800, 600)

        # 设置全局字体
        font = QFont('微软雅黑', 10)
        self.setFont(font)

        layout = QVBoxLayout()

        self.sender_email_label = QLabel('发送者邮箱: ', self)
        layout.addWidget(self.sender_email_label)

        self.email_content_display = QTextEdit(self)
        self.email_content_display.setReadOnly(True)
        layout.addWidget(self.email_content_display)

        self.decrypted_content_display = QTextEdit(self)
        self.decrypted_content_display.setReadOnly(True)
        layout.addWidget(self.decrypted_content_display)

        button_layout = QHBoxLayout()
        self.receive_button = QPushButton('接收邮件', self)
        self.receive_button.clicked.connect(self.receive_email)
        button_layout.addWidget(self.receive_button)

        self.decrypt_button = QPushButton('解密', self)
        self.decrypt_button.clicked.connect(self.decrypt_email)
        button_layout.addWidget(self.decrypt_button)

        layout.addLayout(button_layout)

        self.message_label = QLabel(self)
        layout.addWidget(self.message_label, alignment=Qt.AlignCenter)

        self.setLayout(layout)

        # 设置按钮样式
        self.set_button_styles()

    def set_button_styles(self):
        receive_button_style = """
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

        decrypt_button_style = """
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

        self.receive_button.setStyleSheet(receive_button_style)
        self.decrypt_button.setStyleSheet(decrypt_button_style)

    def receive_email(self):
        try:
            mail = imaplib.IMAP4_SSL('imap.qq.com')
            mail.login('835467248@qq.com', 'fmjuosujlahrbfff')
            mail.select('inbox')

            status, data = mail.search(None, 'FROM "3435519773@qq.com"')
            mail_ids = data[0].split()
            if not mail_ids:
                self.message_label.setText('没有找到符合条件的邮件')
                return

            latest_email_id = mail_ids[-1]

            status, data = mail.fetch(latest_email_id, '(RFC822)')
            raw_email = data[0][1].decode('utf-8')
            msg = email.message_from_string(raw_email)

            sender_email = email.utils.parseaddr(msg['From'])[1]
            self.sender_email_label.setText(f'发送者邮箱: {sender_email}')

            encrypted_content = msg.get_payload(decode=True).decode('utf-8')
            self.email_content_display.setPlainText(encrypted_content)
            self.message_label.setText('邮件接收成功')
        except Exception as e:
            self.message_label.setText(f'邮件接收失败: {e}')

    def decrypt_email(self):
        encrypted_content = self.email_content_display.toPlainText()
        if not encrypted_content:
            self.message_label.setText('没有要解密的邮件内容')
            return

        try:
            encrypted_content_bytes = b64decode(encrypted_content)
            encrypted_aes_key = encrypted_content_bytes[:256]
            nonce = encrypted_content_bytes[256:272]
            tag = encrypted_content_bytes[272:288]
            ciphertext = encrypted_content_bytes[288:]

            # 加载用户的私钥
            private_key_path = os.path.join(os.getcwd(), 'keys', f'{self.current_user.username}_private.pem')
            with open(private_key_path, 'rb') as f:
                private_key = RSA.import_key(f.read())

            # 解密AES密钥
            cipher_rsa = PKCS1_OAEP.new(private_key)
            aes_key = cipher_rsa.decrypt(encrypted_aes_key)

            # 解密邮件内容
            cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # 分离原始邮件内容和签名
            original_email_content = decrypted_data[:-256]
            signature = decrypted_data[-256:]

            # 加载发送者的公钥
            sender_user = get_user_by_email(self.session, '3435519773@qq.com')  # 替换为发送者的用户名
            sender_public_key = RSA.import_key(sender_user.public_key.encode('utf-8'))

            # 验证签名
            h = SHA256.new(original_email_content)
            try:
                pkcs1_15.new(sender_public_key).verify(h, signature)
                self.decrypted_content_display.setPlainText(original_email_content.decode('utf-8'))
                self.message_label.setText('邮件解密和验证成功')
            except (ValueError, TypeError):
                self.message_label.setText('签名验证失败')
        except Exception as e:
            self.message_label.setText(f'邮件解密失败: {e}')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = RegisterLoginWindow()
    window.show()
    sys.exit(app.exec_())
