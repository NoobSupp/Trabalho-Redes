import sys
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QHBoxLayout, QVBoxLayout, QPushButton, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal

class ClientThread(QThread):
    new_message = pyqtSignal(str)

    def __init__(self, client_ip, client_port, server_ip, server_port, parent=None):
        super(ClientThread, self).__init__(parent)
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.client_socket = None

    def create_client(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.server_ip, int(self.server_port)))
            self.new_message.emit(f"Connected to server at {self.server_ip}:{self.server_port}")
        except Exception as e:
            self.new_message.emit(f"Error creating client: {str(e)}")

    def run(self):
        self.create_client()

        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                self.new_message.emit(f"Received: {data.decode('utf-8')}")
            except Exception as e:
                self.new_message.emit(f"Error receiving data: {str(e)}")
                break

    def close_client(self):
        if self.client_socket:
            self.client_socket.close()
            self.new_message.emit("Connection closed")

class ClientApp(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setGeometry(500, 100, 400, 300)
        self.setWindowTitle('Client Application')

        # Client widgets
        client_ip_label = QLabel('Client IP:')
        client_port_label = QLabel('Client Port:')

        self.client_ip_textbox = QLineEdit(self)
        self.client_port_textbox = QLineEdit(self)

        # Server widgets
        server_ip_label = QLabel('Server IP:')
        server_port_label = QLabel('Server Port:')

        self.server_ip_textbox = QLineEdit(self)
        self.server_port_textbox = QLineEdit(self)

        # Buttons
        connect_button = QPushButton('Connect to Server', self)
        disconnect_button = QPushButton('Disconnect', self)

        # Connect buttons to functions
        connect_button.clicked.connect(self.connect_to_server)
        disconnect_button.clicked.connect(self.disconnect_from_server)

        # Chat box
        self.chat_box = QTextEdit(self)
        self.chat_box.setReadOnly(True)

        # Layouts
        client_layout = QVBoxLayout()
        client_layout.addWidget(client_ip_label)
        client_layout.addWidget(self.client_ip_textbox)
        client_layout.addWidget(client_port_label)
        client_layout.addWidget(self.client_port_textbox)

        server_layout = QVBoxLayout()
        server_layout.addWidget(server_ip_label)
        server_layout.addWidget(self.server_ip_textbox)
        server_layout.addWidget(server_port_label)
        server_layout.addWidget(self.server_port_textbox)

        button_layout = QVBoxLayout()
        button_layout.addWidget(connect_button)
        button_layout.addWidget(disconnect_button)

        main_layout = QHBoxLayout()
        main_layout.addLayout(client_layout)
        main_layout.addLayout(server_layout)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.chat_box)

        self.setLayout(main_layout)

        self.client_thread = None  # Reference to the client thread

        self.show()

    def connect_to_server(self):
        client_ip = self.client_ip_textbox.text()
        client_port = self.client_port_textbox.text()
        server_ip = self.server_ip_textbox.text()
        server_port = self.server_port_textbox.text()

        if client_ip and client_port and server_ip and server_port:
            if self.client_thread is None or not self.client_thread.isRunning():
                self.client_thread = ClientThread(client_ip, client_port, server_ip, server_port)
                self.client_thread.new_message.connect(self.update_chat_box)
                self.client_thread.start()
            else:
                self.update_chat_box("Client is already connected.")
        else:
            message = "Please enter both client IP, client Port, server IP, and server Port before connecting."
            self.update_chat_box(message)

    def disconnect_from_server(self):
        if self.client_thread and self.client_thread.isRunning():
            self.client_thread.close_client()
            self.update_chat_box("Disconnected from server.")
        else:
            self.update_chat_box("No connection to close.")

    def update_chat_box(self, message):
        current_text = self.chat_box.toPlainText()
        new_text = f"{current_text}\n{message}"
        self.chat_box.setPlainText(new_text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    client_app = ClientApp()
    sys.exit(app.exec_())
