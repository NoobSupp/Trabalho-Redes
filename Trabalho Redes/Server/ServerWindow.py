import sys
import socket
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QHBoxLayout, QVBoxLayout, QPushButton, QTextEdit
from PyQt5.QtCore import QThread, pyqtSignal

class ServerThread(QThread):
    new_message = pyqtSignal(str)

    def __init__(self, ip, port, parent=None):
        super(ServerThread, self).__init__(parent)
        self.ip = ip
        self.port = port
        self.server_socket = None

    def create_server(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.ip, int(self.port)))
            self.server_socket.listen()
            self.new_message.emit(f"Server listening on {self.ip}:{self.port}")
        except Exception as e:
            self.new_message.emit(f"Error creating server: {str(e)}")

    def run(self):
        self.create_server()

        while True:
            try:
                conn, addr = self.server_socket.accept()
                with conn:
                    self.new_message.emit(f"Connected by {addr}")
            except Exception as e:
                self.new_message.emit(f"Error accepting connection: {str(e)}")

class MyWindow(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()

    def init_ui(self):
        self.setGeometry(100, 100, 400, 300)
        self.setWindowTitle('IP and Port Example')

        # Create labels and textboxes
        ip_label = QLabel('IP:')
        port_label = QLabel('Port:')

        self.ip_textbox = QLineEdit(self)
        self.port_textbox = QLineEdit(self)

        # Create buttons
        open_server_button = QPushButton('Open Server', self)
        close_server_button = QPushButton('Close Server', self)

        # Connect buttons to functions
        open_server_button.clicked.connect(self.open_server)
        close_server_button.clicked.connect(self.close_server_clicked)

        # Create chat box
        self.chat_box = QTextEdit(self)
        self.chat_box.setReadOnly(True)

        # Create layouts
        input_layout = QHBoxLayout()
        input_layout.addWidget(ip_label)
        input_layout.addWidget(self.ip_textbox)
        input_layout.addWidget(port_label)
        input_layout.addWidget(self.port_textbox)

        button_layout = QHBoxLayout()
        button_layout.addWidget(open_server_button)
        button_layout.addWidget(close_server_button)

        main_layout = QVBoxLayout()
        main_layout.addLayout(input_layout)
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.chat_box)

        self.setLayout(main_layout)

        self.server_thread = None  # Reference to the server thread

        self.show()

    def open_server(self):
        ip = self.ip_textbox.text()
        port = self.port_textbox.text()

        if ip and port:
            if self.server_thread is None or not self.server_thread.isRunning():
                self.server_thread = ServerThread(ip, port)
                self.server_thread.new_message.connect(self.update_chat_box)
                self.server_thread.start()
            else:
                self.update_chat_box("Server is already running.")
        else:
            message = "Please enter both IP and Port before opening the server."
            self.update_chat_box(message)

    def close_server_clicked(self):
        if self.server_thread and self.server_thread.isRunning():
            self.server_thread.terminate()
            self.update_chat_box("Server closed.")
        else:
            self.update_chat_box("No server is running.")

    def update_chat_box(self, message):
        current_text = self.chat_box.toPlainText()
        new_text = f"{current_text}\n{message}"
        self.chat_box.setPlainText(new_text)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MyWindow()
    sys.exit(app.exec_())