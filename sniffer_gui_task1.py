import sys
import threading
import socket
from scapy.all import sniff, IP, TCP, Raw
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QTextEdit, QLabel, QLineEdit
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QColor


class PacketSniffer(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("🔍 HTTP Packet Sniffer - Kali Edition")
        self.setGeometry(100, 100, 1200, 700)
        self.sniffing = False
        self.captured_packets = []
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🔐 HTTP Packet Sniffer (with Live Search + Highlights)")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: darkred;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.search_bar = QLineEdit()
        self.search_bar.setPlaceholderText("🔎 Search by IP, Port, Protocol, or Payload...")
        self.search_bar.textChanged.connect(self.apply_search_filter)
        layout.addWidget(self.search_bar)

        self.table = QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels([
            "No", "Src IP", "Src Port", "Dst IP", "Dst Port", "Protocol", "Length", "Payload"
        ])
        self.table.cellClicked.connect(self.display_packet_details)
        layout.addWidget(self.table)

        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setStyleSheet("font-family: Consolas; font-size: 13px;")
        layout.addWidget(self.details_text, stretch=1)

        btn_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start Sniffing")
        self.start_btn.clicked.connect(self.start_sniffing)

        self.stop_btn = QPushButton("⏹ Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_sniffing)

        btn_layout.addWidget(self.start_btn)
        btn_layout.addWidget(self.stop_btn)
        layout.addLayout(btn_layout)

        self.setLayout(layout)

    def start_sniffing(self):
        self.sniffing = True
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.captured_packets = []
        self.table.setRowCount(0)
        threading.Thread(target=self.sniff_packets, daemon=True).start()

    def stop_sniffing(self):
        self.sniffing = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def sniff_packets(self):
        sniff(
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: not self.sniffing,
            filter="tcp port 80"
        )

    def resolve_domain(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Unknown"

    def process_packet(self, packet):
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
        length = len(packet)
        protocol = "HTTP"
        payload = ""
        http_info = ""

        if packet.haslayer(Raw):
            try:
                raw_data = packet[Raw].load.decode(errors='ignore')
                payload = raw_data[:40].replace('\n', ' ')
                if "HTTP" in raw_data or "Host:" in raw_data:
                    http_info += "\n🌐 HTTP HEADERS:\n" + raw_data
                if "POST" in raw_data and ("user" in raw_data.lower() or "pass" in raw_data.lower()):
                    http_info += "\n🔑 Possible Credentials Found:\n"
                    body = raw_data.split('\r\n\r\n', 1)
                    if len(body) > 1:
                        for param in body[1].split("&"):
                            http_info += f"👉 {param.strip()}\n"
            except:
                payload = "[Undecodable Raw]"

        self.captured_packets.append((packet, http_info))

        row = self.table.rowCount()
        self.table.insertRow(row)
        items = [
            QTableWidgetItem(str(row + 1)),
            QTableWidgetItem(src_ip),
            QTableWidgetItem(str(src_port)),
            QTableWidgetItem(dst_ip),
            QTableWidgetItem(str(dst_port)),
            QTableWidgetItem(protocol),
            QTableWidgetItem(str(length)),
            QTableWidgetItem(payload)
        ]
        for col, item in enumerate(items):
            self.table.setItem(row, col, item)

        self.table.scrollToBottom()
        self.apply_search_filter()

    def display_packet_details(self, row, column):
        if row >= len(self.captured_packets):
            return
        packet, http_info = self.captured_packets[row]
        details = f"📦 Packet #{row + 1}\n{'-' * 50}\n"
        if packet.haslayer(IP):
            ip = packet[IP]
            details += f"Src IP: {ip.src} ({self.resolve_domain(ip.src)})\n"
            details += f"Dst IP: {ip.dst} ({self.resolve_domain(ip.dst)})\n"
            details += f"TTL   : {ip.ttl}\n"
            details += f"Len   : {len(packet)}\n"
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            details += "\n🔁 TCP Info:\n"
            details += f"Src Port: {tcp.sport}\n"
            details += f"Dst Port: {tcp.dport}\n"
            details += f"Flags   : {tcp.flags}\n"
        if packet.haslayer(Raw):
            try:
                decoded = packet[Raw].load.decode(errors="ignore")
                details += "\n📦 Payload Preview:\n" + decoded[:500]
            except:
                details += "\n📦 Payload Preview: [Undecodable]"
        if http_info:
            details += http_info
        self.details_text.setPlainText(details)

    def apply_search_filter(self):
        query = self.search_bar.text().lower()
        for row in range(self.table.rowCount()):
            matched = False
            for col in range(self.table.columnCount()):
                item = self.table.item(row, col)
                if item:
                    text = item.text().lower()
                    item.setBackground(QColor("white"))  # reset color

                    if query and query in text:
                        matched = True
                        # Color highlight rules
                        if "cookie" in text:
                            item.setBackground(QColor("lightgreen"))
                        elif any(err in text for err in ["fail", "unauthorized", "error"]):
                            item.setBackground(QColor("lightcoral"))
                        else:
                            item.setBackground(QColor("yellow"))

            self.table.setRowHidden(row, not matched if query else False)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = PacketSniffer()
    window.show()
    sys.exit(app.exec_())
