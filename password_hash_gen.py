#!/usr/bin/env python3

import sys
import hashlib
import hmac
from enum import Enum
from PyQt6.QtWidgets import (
    QApplication,
    QRadioButton,
    QButtonGroup,
    QLabel,
    QComboBox,
    QFrame,
    QWidget,
    QPushButton,
    QListWidget,
    QVBoxLayout,
    QFileDialog,
    QHBoxLayout,
    QLineEdit,
    QCheckBox,
)


TITLE = "Password Hash Generator"
VERSION = "v1.0.1"

BLOCK_SIZE = 65536


class HASH_ALGORITHEM(Enum):
    MD5SUM = 1
    SHA256 = 2
    SHA512 = 3


class HasUtils:
    @staticmethod
    def gen_str_hash(alg: HASH_ALGORITHEM, text: str):
        if alg == HASH_ALGORITHEM.MD5SUM:
            return hashlib.md5(text.encode("utf-8")).hexdigest()
        elif alg == HASH_ALGORITHEM.SHA256:
            return hashlib.sha256(text.encode("utf-8")).hexdigest()
        elif alg == HASH_ALGORITHEM.SHA512:
            return hashlib.sha512(text.encode("utf-8")).hexdigest()
        else:
            return None

    @staticmethod
    def gen_file_hash(file_list, alg: HASH_ALGORITHEM, cycles=1):
        if len(file_list) == 0:
            return ""

        hash = HasUtils.get_hash_algorithem(alg)
        file_hashs = []

        for file in sorted(file_list):
            file_hash = HasUtils.__gen_file_hash(file, (hash))
            for cycle_count in range(1, int(cycles)):
                file_hash = HasUtils.gen_str_hash(alg, file_hash)
            file_hashs.append(file_hash)

        if len(file_list) == 1:
            return file_hashs[0]
        else:
            return HasUtils.gen_str_hash(alg, "".join(file_hashs))

    @staticmethod
    def gen_question_hash(question_list, alg: HASH_ALGORITHEM, cycles=1):
        if len(question_list) == 0:
            return ""

        q_hashs = []

        for question in question_list:
            question_hash = HasUtils.gen_str_hash(alg, question)
            for cycle_count in range(1, int(cycles)):
                question_hash = HasUtils.gen_str_hash(alg, question_hash)
            q_hashs.append(question_hash)

        if len(question_list) == 1:
            return q_hashs[0]
        else:
            return HasUtils.gen_str_hash(alg, "".join(q_hashs))

    @staticmethod
    def get_hash_algorithem(alg: HASH_ALGORITHEM):
        if alg == HASH_ALGORITHEM.MD5SUM:
            return hashlib.md5()
        elif alg == HASH_ALGORITHEM.SHA256:
            return hashlib.sha256()
        elif alg == HASH_ALGORITHEM.SHA512:
            return hashlib.sha512()
        else:
            return None

    @staticmethod
    def get_hash_algorithem_lib(alg: HASH_ALGORITHEM):
        if alg == HASH_ALGORITHEM.MD5SUM:
            return hashlib.md5
        elif alg == HASH_ALGORITHEM.SHA256:
            return hashlib.sha256
        elif alg == HASH_ALGORITHEM.SHA512:
            return hashlib.sha512
        else:
            return None

    @staticmethod
    def __gen_file_hash(file, hash):
        with open(file, "rb") as f:
            for block in iter(lambda: f.read(BLOCK_SIZE), b""):
                hash.update(block)
        return hash.hexdigest()

    @staticmethod
    def get_hmac_digest(alg: HASH_ALGORITHEM, password_list, key):
        password = "".join(password_list)
        alg = HasUtils.get_hash_algorithem_lib(alg)

        if len(password_list) == 0 or alg is None or len(password) == 0:
            return ""

        # Create a new HMAC object using the hash algorithem
        hmac_obj = hmac.new(key.encode("utf-8"), password.encode("utf-8"), alg)
        return hmac_obj.hexdigest()


class FileSelector(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.selected_files = set()
        self.selected_hash = HASH_ALGORITHEM.MD5SUM

    def init_ui(self):
        self.setWindowTitle(f"{TITLE} : {VERSION}")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout()

        layout.addWidget(QLabel("Key files :"))
        self.select_button = QPushButton("Select Files")
        self.select_button.clicked.connect(self.select_files)
        layout.addWidget(self.select_button)

        self.file_list = QListWidget()
        self.file_list.itemDoubleClicked.connect(self.remove_item)

        layout.addWidget(self.file_list)
        layout.addWidget(QLabel(" "))
        layout.addWidget(QLabel("Password : "))
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("")
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.password_input)

        # Adding a horizontal separator
        separator1 = QFrame()
        separator1.setFrameShape(QFrame.Shape.HLine)
        separator1.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator1)

        layout.addWidget(QLabel("Anwer to Q1 :"))

        self.q1 = QLineEdit()
        self.q1.setPlaceholderText("")
        self.q1.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.q1)

        layout.addWidget(QLabel("Anwer to Q2 :"))
        self.q2 = QLineEdit()
        self.q2.setPlaceholderText("")
        self.q2.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.q2)

        layout.addWidget(QLabel("Anwer to Q3 :"))
        self.q3 = QLineEdit()
        self.q3.setPlaceholderText("")
        self.q3.setEchoMode(QLineEdit.EchoMode.Password)
        layout.addWidget(self.q3)

        checkbox_layout = QHBoxLayout()
        checkbox_layout.addStretch()
        self.show_password_checkbox = QCheckBox("Show Password")
        self.show_password_checkbox.stateChanged.connect(
            self.toggle_password_visibility
        )
        checkbox_layout.addWidget(self.show_password_checkbox)
        checkbox_layout.addStretch()
        layout.addLayout(checkbox_layout)
        layout.addWidget(QLabel(" "))

        layout.addWidget(QLabel("Number of iterations :"))
        self.combo_count = QComboBox()
        self.combo_count.addItems([str(i) for i in range(1, 11)])
        layout.addWidget(self.combo_count)

        layout.addWidget(QLabel(" "))
        # Create radio buttons
        layout.addWidget(QLabel("Hasing Algorithem :"))
        self.hahs_md5sum = QRadioButton("MD5SUM")
        self.hahs_md5sum.setChecked(True)
        self.hash_sha256 = QRadioButton("SHA 256")
        self.hash_sha512 = QRadioButton("SHA 512")
        layout.addWidget(self.hahs_md5sum)
        layout.addWidget(self.hash_sha256)
        layout.addWidget(self.hash_sha512)

        self.hash_algo_group = QButtonGroup(self)
        self.hash_algo_group.addButton(self.hahs_md5sum)
        self.hash_algo_group.addButton(self.hash_sha256)
        self.hash_algo_group.addButton(self.hash_sha512)
        self.hash_algo_group.buttonClicked.connect(self.on_hash_change)

        layout.addWidget(QLabel(" "))
        self.submit_button = QPushButton("Generate")
        self.submit_button.clicked.connect(self.generate_passwod)

        layout.addWidget(self.submit_button)

        separator = QFrame()
        separator.setFrameShape(QFrame.Shape.HLine)
        separator.setFrameShadow(QFrame.Shadow.Sunken)
        layout.addWidget(separator)

        layout.addWidget(QLabel("Generated password :"))
        self.final_password = QLineEdit()
        self.final_password.setReadOnly(True)
        self.final_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.final_password.textChanged.connect(self.on_pass_change)
        layout.addWidget(self.final_password)

        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.clicked.connect(self.copy_to_clipboard)
        layout.addWidget(self.copy_button)

        layout.addWidget(QLabel(" "))
        self.clear_button = QPushButton("Clear")
        self.clear_button.clicked.connect(self.clear_form)
        layout.addWidget(self.clear_button)

        self.setLayout(layout)

    def on_pass_change(self, text):
        if len(text) > 0:
            self.copy_button.setEnabled(True)
        else:
            self.copy_button.setEnabled(False)
            self.remove_from_clipboard()

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.final_password.text())

    def clear_form(self):
        # clear text
        self.q1.clear()
        self.q2.clear()
        self.q3.clear()
        self.password_input.clear()
        self.show_password_checkbox.setChecked(False)
        # clear files
        # reset list
        # clear clipboard
        self.file_list.clear()
        self.selected_files.clear()
        self.selected_hash = HASH_ALGORITHEM.MD5SUM
        self.combo_count.setCurrentIndex(0)

        self.hahs_md5sum.setChecked(True)
        self.hash_sha256.setChecked(False)
        self.hash_sha512.setChecked(False)

        self.final_password.clear()
        self.remove_from_clipboard()

    def remove_from_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText("")

    def toggle_password_visibility(self, state):
        if state == 2:  # Checked
            self.password_input.setEchoMode(QLineEdit.EchoMode.Normal)
            self.q1.setEchoMode(QLineEdit.EchoMode.Normal)
            self.q2.setEchoMode(QLineEdit.EchoMode.Normal)
            self.q3.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
            self.q1.setEchoMode(QLineEdit.EchoMode.Password)
            self.q2.setEchoMode(QLineEdit.EchoMode.Password)
            self.q3.setEchoMode(QLineEdit.EchoMode.Password)

    def select_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        if files:
            self.selected_files.update(files)
            self.file_list.clear()
            self.file_list.addItems(self.selected_files)

    def generate_passwod(self):
        final_pword = []
        selected_hash = self.selected_hash
        iterations = self.combo_count.currentText()
        # 1. generate the hash of each file (iterate by number of times)
        final_pword.append(
            HasUtils.gen_file_hash(
                sorted(self.selected_files), selected_hash, iterations
            )
        )

        # 2 generate the hash of the q1,q2,q3 (if exists) (iterate by number of times)
        final_pword.append(
            HasUtils.gen_question_hash(
                self.__get_questions(), selected_hash, iterations
            )
        )

        # 3 use the password as the HAMC to generate the final hash of the combind hashs (files + q1 + q2 + q3)
        self.final_password.setText(
            HasUtils.get_hmac_digest(
                selected_hash, final_pword, self.password_input.text().strip()
            )
        )

    def __get_questions(self):
        answer_list = []
        if self.q1.text() != "":
            answer_list.append(self.q1.text().strip())
        if self.q2.text() != "":
            answer_list.append(self.q2.text().strip())
        if self.q3.text() != "":
            answer_list.append(self.q3.text().strip())
        return answer_list

    def __set_hash(self, text):
        if text == "MD5SUM":
            self.selected_hash = HASH_ALGORITHEM.MD5SUM
        elif text == "SHA 256":
            self.selected_hash = HASH_ALGORITHEM.SHA256
        elif text == "SHA 512":
            self.selected_hash = HASH_ALGORITHEM.SHA512

    def on_hash_change(self, button):
        self.final_password.setText("")
        self.__set_hash(button.text())

    def remove_item(self, item):
        self.file_list.takeItem(self.file_list.row(item))
        self.selected_files.remove(item.text())


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileSelector()
    window.show()
    sys.exit(app.exec())
