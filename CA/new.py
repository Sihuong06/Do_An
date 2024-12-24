from PyQt5.QtWidgets import QApplication, QVBoxLayout, QFormLayout, QLineEdit, QComboBox, QPushButton, QWidget,QFileDialog, QMessageBox
from PyQt5.QtCore import Qt
import requests
class KeyPairApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Generate and Expire Key Pair")

        # Main layout
        layout = QVBoxLayout()

        # Verification code input
        form_layout = QFormLayout()
        self.verification_code_input = QLineEdit()
        self.verification_code_input.setPlaceholderText("Enter Verification Code")
        form_layout.addRow("Verification Code:", self.verification_code_input)

        # Algorithm selection
        self.algorithm_select = QComboBox()
        self.algorithm_select.addItems(["RSA", "DSA", "ECDSA"])
        self.algorithm_select.currentIndexChanged.connect(self.update_bit_size_options)
        form_layout.addRow("Algorithm:", self.algorithm_select)

        # Bit size selection
        self.bit_size_select = QComboBox()
        self.update_bit_size_options()  # Initialize with default algorithm options
        form_layout.addRow("Bit Size:", self.bit_size_select)

        # Submit button
        self.submit_button = QPushButton("Generate Key Pair")
        self.submit_button.clicked.connect(self.generate_keypair)

        # Add widgets to layout
        layout.addLayout(form_layout)
        layout.addWidget(self.submit_button, alignment=Qt.AlignCenter)

        self.setLayout(layout)

    def update_bit_size_options(self):
        algorithm = self.algorithm_select.currentText()
        self.bit_size_select.clear()

        if algorithm in ["RSA", "DSA"]:
            self.bit_size_select.addItems(["1024", "2048", "3072", "4096"])
        elif algorithm == "ECDSA":
            self.bit_size_select.addItems(["256", "384", "521"])



    def generate_keypair(self):
        # Get input values
        verification_code = self.verification_code_input.text()
        algorithm = self.algorithm_select.currentText()
        bit_size = self.bit_size_select.currentText()

        # Send these values to the backend API
        url = "http://127.0.0.1:8000/keypair/generate-keypair/"
        data = {
            "verification_code": verification_code,
            "algorithm": algorithm,
            "bit_size": bit_size
        }

        try:
            response = requests.post(url, json=data)
            response.raise_for_status()  # Raise an error for HTTP errors

            # Parse response data
            result = response.json()
            private_key = result.get("private_key")
            if private_key:
                # Save the private key to a file
                save_path, _ = QFileDialog.getSaveFileName(
                    self, 
                    "Save Private Key", 
                    f"private_key_{algorithm}.pem", 
                    "PEM Files (*.pem)"
                )
                if save_path:
                    with open(save_path, "w") as file:
                        file.write(private_key)
                    QMessageBox.information(self, "Success", "Key pair generated and private key saved successfully!")
                else:
                    QMessageBox.warning(self, "Cancelled", "Save operation cancelled.")
            else:
                QMessageBox.critical(self, "Error", "Failed to get private key from server response.")

        except requests.exceptions.RequestException as e:
            QMessageBox.critical(self, "Error", f"An error occurred: {str(e)}")

if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    window = KeyPairApp()
    window.show()
    sys.exit(app.exec_())
