import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QTableWidget, QTableWidgetItem, QPushButton, 
                             QLineEdit, QHBoxLayout, QComboBox, QHeaderView, QLabel)
from PySide6.QtCore import Qt, QTimer, QSortFilterProxyModel
from PySide6.QtGui import QPixmap
import psutil
import socket
import subprocess
from datetime import datetime
import requests
import json
from functools import lru_cache

class NetworkMonitor(QMainWindow):
    THREAT_LIST_URL = "https://www.spamhaus.org/drop/drop.txt"
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Monitor de Tráfico de Red Avanzado")
        self.setGeometry(100, 100, 1500, 700)
        
        # Widget principal
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Controles de filtrado
        self.threat_ips = set()
        self.update_threat_list()
        filter_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Buscar...")
        self.search_input.textChanged.connect(self.apply_filters)
        
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["Todos", "TCP", "UDP"])
        self.protocol_filter.currentTextChanged.connect(self.apply_filters)
        
        self.direction_filter = QComboBox()
        self.direction_filter.addItems(["Todas", "Entrada", "Salida"])
        self.direction_filter.currentTextChanged.connect(self.apply_filters)
        
        filter_layout.addWidget(self.search_input)
        filter_layout.addWidget(self.protocol_filter)
        filter_layout.addWidget(self.direction_filter)
        
        # Tabla de conexiones con nuevas columnas
        self.table = QTableWidget()
        self.table.setColumnCount(13)
        self.table.setHorizontalHeaderLabels([
            "Protocolo", "IP Local", "Puerto Local", 
            "IP Remota", "Puerto Remoto", "Estado",
            "Proceso", "País", "Ciudad", 
            "ISP", "Organización", "Amenaza",
            "Tiempo"
        ])
        
        # Configurar comportamiento de la tabla
        header = self.table.horizontalHeader()
        for i in range(13):
            header.setSectionResizeMode(i, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSortingEnabled(True)
        
        # Botones
        button_layout = QHBoxLayout()
        self.block_button = QPushButton("Bloquear Conexión Seleccionada")
        self.block_button.clicked.connect(self.block_connection)
        self.refresh_button = QPushButton("Actualizar Datos IP")
        self.refresh_button.clicked.connect(self.refresh_ip_data)
        
        button_layout.addWidget(self.block_button)
        button_layout.addWidget(self.refresh_button)
        
        layout.addLayout(filter_layout)
        layout.addWidget(self.table)
        layout.addLayout(button_layout)
        
        # Timer para actualización automática
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_connections)
        self.timer.start(2000)
        
        self.blocked_connections = set()
        
    @lru_cache(maxsize=1024)
    def get_ip_info(self, ip):
        """Obtiene información detallada de una IP usando la API de IPApi"""
        try:
            if self._is_private_ip(ip):
                return {
                    'country': 'Local',
                    'city': 'Red Local',
                    'isp': 'Privado',
                    'org': 'Red Privada',
                    'threat': 'No'
                }
            
            response = requests.get(f'http://ip-api.com/json/{ip}')
            if response.status_code == 200:
                data = response.json()
                return {
                    'country': data.get('country', 'Desconocido'),
                    'city': data.get('city', 'Desconocido'),
                    'isp': data.get('isp', 'Desconocido'),
                    'org': data.get('org', 'Desconocido'),
                    'threat': self.check_ip_threat(ip)
                }
        except Exception as e:
            print(f"Error al obtener información de IP {ip}: {e}")
        
        return {
            'country': 'Error',
            'city': 'Error',
            'isp': 'Error',
            'org': 'Error',
            'threat': 'Desconocido'
        }
    
    def _is_private_ip(self, ip):
        """Verifica si una IP es privada"""
        try:
            ip_parts = ip.split('.')
            return (
                ip.startswith('10.') or
                ip.startswith('172.16.') or
                ip.startswith('192.168.') or
                ip.startswith('127.') or
                ip == '::1' or
                ip == 'localhost'
            )
        except:
            return False
    
    def update_threat_list(self):
        """Descarga y almacena la lista de IPs sospechosas."""
        try:
            import urllib.request
            with urllib.request.urlopen(self.THREAT_LIST_URL) as response:
                self.threat_ips = {line.decode('utf-8').strip() for line in response if not line.startswith(b";")}
        except Exception as e:
            print(f"Error al descargar la lista de amenazas: {e}")
            self.threat_ips = set()
    
    @lru_cache(maxsize=1024)
    def check_ip_threat(self, ip: str) -> str:
        """Verifica si una IP está en listas negras descargadas."""
        try:
            ip = socket.gethostbyname(ip)  # Resuelve dominios a IP
            return "Amenaza detectada" if ip in self.threat_ips else "Segura"
        except Exception as e:
            print(f"Error al verificar la IP {ip}: {e}")
            return "Error"
    
    def update_connections(self):
        """Actualiza la lista de conexiones en la tabla"""
        connections = psutil.net_connections(kind='inet')
        self.table.setRowCount(0)
        
        for conn in connections:
            if not self._passes_filters(conn):
                continue
                
            row_position = self.table.rowCount()
            self.table.insertRow(row_position)
            
            # Datos básicos de conexión
            self.table.setItem(row_position, 0, QTableWidgetItem(self._get_protocol(conn)))
            
            if conn.laddr:
                self.table.setItem(row_position, 1, QTableWidgetItem(conn.laddr.ip))
                self.table.setItem(row_position, 2, QTableWidgetItem(str(conn.laddr.port)))
            
            remote_ip = ""
            if conn.raddr:
                remote_ip = conn.raddr.ip
                self.table.setItem(row_position, 3, QTableWidgetItem(remote_ip))
                self.table.setItem(row_position, 4, QTableWidgetItem(str(conn.raddr.port)))
            
            self.table.setItem(row_position, 5, QTableWidgetItem(conn.status))
            
            # Proceso
            try:
                if conn.pid:
                    process = psutil.Process(conn.pid)
                    self.table.setItem(row_position, 6, QTableWidgetItem(process.name()))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            
            # Información geográfica y de amenazas
            if remote_ip:
                ip_info = self.get_ip_info(remote_ip)
                self.table.setItem(row_position, 7, QTableWidgetItem(ip_info['country']))
                self.table.setItem(row_position, 8, QTableWidgetItem(ip_info['city']))
                self.table.setItem(row_position, 9, QTableWidgetItem(ip_info['isp']))
                self.table.setItem(row_position, 10, QTableWidgetItem(ip_info['org']))
                self.table.setItem(row_position, 11, QTableWidgetItem(ip_info['threat']))
            
            # Tiempo
            self.table.setItem(row_position, 12, QTableWidgetItem(datetime.now().strftime('%H:%M:%S')))
    
    def refresh_ip_data(self):
        """Actualiza la información de IP para las conexiones seleccionadas"""
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return
            
        # Limpiar el cache para forzar una nueva consulta
        self.get_ip_info.cache_clear()
        self.check_ip_threat.cache_clear()
        
        # Actualizar las conexiones
        self.update_connections()
    
    def _passes_filters(self, conn):
        """Verifica si la conexión pasa los filtros actuales"""
        if self.protocol_filter.currentText() != "Todos":
            if self._get_protocol(conn) != self.protocol_filter.currentText():
                return False
        
        direction = self.direction_filter.currentText()
        if direction != "Todas":
            if direction == "Entrada" and conn.status != "LISTEN":
                return False
            if direction == "Salida" and conn.status == "LISTEN":
                return False
        
        search_text = self.search_input.text().lower()
        if search_text:
            if conn.laddr and search_text in conn.laddr.ip.lower():
                return True
            if conn.raddr and search_text in conn.raddr.ip.lower():
                return True
            return False
        
        return True
    
    def _get_protocol(self, conn):
        """Obtiene el protocolo de la conexión"""
        return "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
    
    def block_connection(self):
        """Bloquea la conexión seleccionada usando iptables/firewall"""
        selected_rows = self.table.selectedItems()
        if not selected_rows:
            return
        
        row = selected_rows[0].row()
        ip = self.table.item(row, 3).text()  # IP remota
        port = self.table.item(row, 4).text()  # Puerto remoto
        
        if sys.platform.startswith('linux'):
            cmd = f"sudo iptables -A OUTPUT -d {ip} -p tcp --dport {port} -j DROP"
            try:
                subprocess.run(cmd.split(), check=True)
                self.blocked_connections.add((ip, port))
            except subprocess.CalledProcessError:
                print(f"Error al bloquear la conexión: {ip}:{port}")
        elif sys.platform.startswith('win'):
            cmd = (f'netsh advfirewall firewall add rule name="Block {ip}:{port}" '
                  f'dir=out action=block protocol=TCP remoteip={ip} remoteport={port}')
            try:
                subprocess.run(cmd, check=True)
                self.blocked_connections.add((ip, port))
            except subprocess.CalledProcessError:
                print(f"Error al bloquear la conexión: {ip}:{port}")

    def apply_filters(self):
        """Aplica los filtros de búsqueda a la tabla"""
        self.update_connections()

def main():
    app = QApplication(sys.argv)
    window = NetworkMonitor()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()