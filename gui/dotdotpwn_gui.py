#!/usr/bin/env python3
"""
DotDotPwn GUI Application

A comprehensive cross-platform GUI for the DotDotPwn directory traversal fuzzer.
Built with PyQt6 for optimal performance and user experience.

Features:
- Intuitive interface with guided workflows
- Real-time output monitoring
- Advanced scan configuration
- Report generation and export
- Resource monitoring
- Cross-platform compatibility
"""

import sys
import os
import json
import time
import threading
import subprocess
import queue
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime

# PyQt6 imports
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTabWidget, QGroupBox, QLabel, QPushButton, QLineEdit, QComboBox,
    QSpinBox, QCheckBox, QTextEdit, QProgressBar, QTableWidget,
    QTableWidgetItem, QFileDialog, QMessageBox, QSplitter,
    QFrame, QScrollArea, QGridLayout, QFormLayout, QSlider,
    QTreeWidget, QTreeWidgetItem, QStatusBar, QMenuBar, QMenu,
    QToolBar, QButtonGroup, QRadioButton, QPlainTextEdit
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSettings, QSize, QPoint,
    QPropertyAnimation, QEasingCurve, QRect, QRunnable, QThreadPool,
    QRegularExpression
)
from PyQt6.QtGui import (
    QIcon, QFont, QPixmap, QPalette, QColor, QAction,
    QTextCursor, QSyntaxHighlighter, QTextCharFormat,
    QPainter, QLinearGradient
)

# Third-party imports
import qtawesome as qta
import qdarkstyle
import pyqtgraph as pg

# Add src directory to Python path
project_root = Path(__file__).parent.parent
src_path = project_root / "src"
sys.path.insert(0, str(src_path))


@dataclass
class ScanConfiguration:
    """Scan configuration data class"""
    module: str = "http"
    target_host: str = ""
    target_port: int = 80
    target_file: str = "/etc/passwd"
    target_url: str = ""
    pattern: str = "root:"
    depth: int = 6
    os_type: str = "unix"
    use_ssl: bool = False
    delay: float = 0.3
    break_on_first: bool = False
    continue_on_error: bool = True
    quiet_mode: bool = False
    extra_files: bool = False
    extension: str = ""
    username: str = ""
    password: str = ""
    http_method: str = "GET"
    user_agent: str = ""
    payload_file: str = ""
    os_detection: bool = False
    service_detection: bool = False
    bisection: bool = False
    output_format: str = "text"
    output_file: str = ""


class OutputHighlighter(QSyntaxHighlighter):
    """Syntax highlighter for scan output"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_highlighting_rules()
    
    def setup_highlighting_rules(self):
        """Setup highlighting rules for different output types"""
        self.highlighting_rules = []
        
        # Success patterns (green)
        success_format = QTextCharFormat()
        success_format.setForeground(QColor(0, 200, 0))
        success_format.setFontWeight(QFont.Weight.Bold)
        success_patterns = [r'\[✓\].*', r'SUCCESS.*', r'FOUND.*', r'\[\+\].*']
        
        for pattern in success_patterns:
            self.highlighting_rules.append((QRegularExpression(pattern), success_format))
        
        # Error patterns (red)
        error_format = QTextCharFormat()
        error_format.setForeground(QColor(255, 100, 100))
        error_format.setFontWeight(QFont.Weight.Bold)
        error_patterns = [r'\[✗\].*', r'ERROR.*', r'FAILED.*', r'\[\-\].*']
        
        for pattern in error_patterns:
            self.highlighting_rules.append((QRegularExpression(pattern), error_format))
        
        # Info patterns (blue)
        info_format = QTextCharFormat()
        info_format.setForeground(QColor(100, 150, 255))
        info_patterns = [r'\[i\].*', r'INFO.*', r'\[\*\].*']
        
        for pattern in info_patterns:
            self.highlighting_rules.append((QRegularExpression(pattern), info_format))
        
        # Warning patterns (yellow)
        warning_format = QTextCharFormat()
        warning_format.setForeground(QColor(255, 200, 0))
        warning_patterns = [r'\[!\].*', r'WARNING.*', r'WARN.*']
        
        for pattern in warning_patterns:
            self.highlighting_rules.append((QRegularExpression(pattern), warning_format))
    
    def highlightBlock(self, text):
        """Apply highlighting to text block"""
        for pattern, format_obj in self.highlighting_rules:
            expression = pattern
            match_iterator = expression.globalMatch(text)
            while match_iterator.hasNext():
                match = match_iterator.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format_obj)


class ResourceMonitor(QThread):
    """Thread for monitoring system resources"""
    
    resource_updated = pyqtSignal(dict)
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.scan_process = None
    
    def set_scan_process(self, process):
        """Set the scan process to monitor"""
        self.scan_process = process
    
    def run(self):
        """Monitor resources in background thread"""
        try:
            import psutil
        except ImportError:
            return
        
        while self.running:
            try:
                # System resources
                cpu_percent = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                
                resource_data = {
                    'cpu_percent': cpu_percent,
                    'memory_percent': memory.percent,
                    'memory_available': memory.available // 1024 // 1024,  # MB
                    'process_cpu': 0,
                    'process_memory': 0
                }
                
                # Process specific resources
                if self.scan_process:
                    try:
                        process = psutil.Process(self.scan_process.pid)
                        resource_data['process_cpu'] = process.cpu_percent()
                        resource_data['process_memory'] = process.memory_info().rss // 1024 // 1024  # MB
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
                
                self.resource_updated.emit(resource_data)
                self.msleep(2000)  # Update every 2 seconds
                
            except Exception as e:
                print(f"Resource monitoring error: {e}")
                self.msleep(5000)
    
    def stop(self):
        """Stop resource monitoring"""
        self.running = False


class ScanWorker(QThread):
    """Worker thread for running scans"""
    
    output_ready = pyqtSignal(str)
    scan_finished = pyqtSignal(int, str)
    scan_started = pyqtSignal()
    progress_updated = pyqtSignal(int, str)
    
    def __init__(self, config: ScanConfiguration, python_cmd: str, script_path: str):
        super().__init__()
        self.config = config
        self.python_cmd = python_cmd
        self.script_path = script_path
        self.process = None
        self.is_running = False
    
    def run(self):
        """Run the scan in background thread"""
        try:
            # Build command
            cmd = self.build_command()
            
            self.scan_started.emit()
            self.progress_updated.emit(10, "Starting scan...")
            
            # Start process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
            
            self.is_running = True
            self.progress_updated.emit(20, "Scan in progress...")
            
            # Read output line by line
            for line in iter(self.process.stdout.readline, ''):
                if not self.is_running:
                    break
                
                self.output_ready.emit(line.rstrip())
                
                # Update progress based on output
                if "Creating Traversal patterns" in line:
                    self.progress_updated.emit(40, "Creating traversal patterns...")
                elif "Multiplying" in line:
                    self.progress_updated.emit(60, "Multiplying patterns...")
                elif "DONE" in line:
                    self.progress_updated.emit(80, "Pattern generation complete...")
            
            # Wait for process to finish
            return_code = self.process.wait()
            self.progress_updated.emit(100, "Scan completed")
            
            self.scan_finished.emit(return_code, "Scan completed successfully" if return_code == 0 else "Scan failed")
            
        except Exception as e:
            self.scan_finished.emit(-1, f"Error running scan: {str(e)}")
        finally:
            self.is_running = False
            self.process = None
    
    def build_command(self) -> List[str]:
        """Build command line arguments from configuration"""
        cmd = [self.python_cmd, self.script_path]
        
        if self.config.module == "stdout":
            cmd.extend(["generate"])
            cmd.extend(["--os-type", self.config.os_type])
            cmd.extend(["--depth", str(self.config.depth)])
            
            if self.config.target_file:
                cmd.extend(["--specific-file", self.config.target_file])
            
            if self.config.extra_files:
                cmd.append("--extra-files")
            
            if self.config.extension:
                cmd.extend(["--extension", self.config.extension])
            
            if self.config.output_file:
                cmd.extend(["--output-file", self.config.output_file])
        
        else:
            # Main scan command
            cmd.extend(["main"])
            cmd.extend(["--module", self.config.module])
            
            if self.config.target_host:
                cmd.extend(["--host", self.config.target_host])
            
            if self.config.target_port != 80:
                cmd.extend(["--port", str(self.config.target_port)])
            
            if self.config.target_file:
                cmd.extend(["--file", self.config.target_file])
            
            if self.config.target_url:
                cmd.extend(["--url", self.config.target_url])
            
            if self.config.pattern:
                cmd.extend(["--pattern", self.config.pattern])
            
            cmd.extend(["--depth", str(self.config.depth)])
            cmd.extend(["--os-type", self.config.os_type])
            
            if self.config.use_ssl:
                cmd.append("--ssl")
            
            if self.config.delay != 0.3:
                cmd.extend(["--delay", str(self.config.delay)])
            
            if self.config.break_on_first:
                cmd.append("--break-on-first")
            
            if self.config.continue_on_error:
                cmd.append("--continue-on-error")
            
            if self.config.quiet_mode:
                cmd.append("--quiet")
            
            if self.config.extra_files:
                cmd.append("--extra-files")
            
            if self.config.extension:
                cmd.extend(["--extension", self.config.extension])
            
            if self.config.username:
                cmd.extend(["--username", self.config.username])
            
            if self.config.password:
                cmd.extend(["--password", self.config.password])
            
            if self.config.http_method != "GET":
                cmd.extend(["--method", self.config.http_method])
            
            if self.config.user_agent:
                cmd.extend(["--user-agent", self.config.user_agent])
            
            if self.config.payload_file:
                cmd.extend(["--payload", self.config.payload_file])
            
            if self.config.os_detection:
                cmd.append("--os-detection")
            
            if self.config.service_detection:
                cmd.append("--service-detection")
            
            if self.config.bisection:
                cmd.append("--bisection")
            
            if self.config.output_file:
                cmd.extend(["--report", self.config.output_file])
                cmd.extend(["--format", self.config.output_format])
        
        return cmd
    
    def stop_scan(self):
        """Stop the running scan"""
        self.is_running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()


class DotDotPwnGUI(QMainWindow):
    """Main GUI application window"""
    
    def __init__(self):
        super().__init__()
        
        # Initialize variables
        self.config = ScanConfiguration()
        self.scan_worker = None
        self.resource_monitor = ResourceMonitor()
        self.scan_history = []
        
        # Get paths
        self.project_root = Path(__file__).parent.parent
        self.python_cmd = sys.executable  # Use the currently running Python interpreter
        self.script_path = str(self.project_root / "dotdotpwn.py")
        
        # Settings
        self.settings = QSettings("DotDotPwn", "GUI")
        
        # Initialize UI
        self.init_ui()
        self.init_menubar()
        self.init_toolbar()
        self.init_statusbar()
        
        # Start resource monitoring
        self.resource_monitor.resource_updated.connect(self.update_resource_display)
        self.resource_monitor.start()
        
        # Load settings
        self.load_settings()
        
        # Set window properties
        self.setWindowTitle("DotDotPwn GUI - Directory Traversal Fuzzer")
        self.setWindowIcon(qta.icon('fa5s.bug'))
        
        # Make window size adaptive to screen size
        screen = QApplication.primaryScreen().availableGeometry()
        width = min(int(screen.width() * 0.85), 1600)  # 85% of screen width, max 1600
        height = min(int(screen.height() * 0.85), 1000)  # 85% of screen height, max 1000
        self.resize(width, height)
        
        # Center the window
        self.move(
            (screen.width() - width) // 2,
            (screen.height() - height) // 2
        )
        
        # Apply dark theme
        self.setStyleSheet(qdarkstyle.load_stylesheet_pyqt6())
    
    def init_ui(self):
        """Initialize the main user interface"""
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        main_layout = QHBoxLayout(central_widget)
        
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - Configuration
        left_panel = self.create_configuration_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Output and monitoring
        right_panel = self.create_output_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions (50/50 split)
        splitter.setStretchFactor(0, 1)  # Config panel
        splitter.setStretchFactor(1, 1)  # Output panel
        
        # Set initial sizes for better 50/50 distribution
        screen = QApplication.primaryScreen().availableGeometry()
        total_width = min(int(screen.width() * 0.85), 1600)
        splitter.setSizes([int(total_width * 0.5), int(total_width * 0.5)])
        
    def create_configuration_panel(self) -> QWidget:
        """Create the configuration panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Title
        title = QLabel("🎯 Scan Configuration")
        title.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        # Scroll area for configuration options
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        config_widget = QWidget()
        config_layout = QVBoxLayout(config_widget)
        
        # Basic Configuration
        basic_group = self.create_basic_config_group()
        config_layout.addWidget(basic_group)
        
        # Target Configuration
        target_group = self.create_target_config_group()
        config_layout.addWidget(target_group)
        
        # Advanced Configuration
        advanced_group = self.create_advanced_config_group()
        config_layout.addWidget(advanced_group)
        
        # Authentication
        auth_group = self.create_auth_config_group()
        config_layout.addWidget(auth_group)
        
        # Output Configuration
        output_group = self.create_output_config_group()
        config_layout.addWidget(output_group)
        
        config_layout.addStretch()
        scroll.setWidget(config_widget)
        layout.addWidget(scroll)
        
        # Control buttons
        button_layout = QHBoxLayout()
        
        self.start_button = QPushButton("🚀 Start Scan")
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #2d5f3f;
                border: 2px solid #4a8f6f;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #3d7f5f;
            }
            QPushButton:pressed {
                background-color: #1d4f2f;
            }
        """)
        self.start_button.clicked.connect(self.start_scan)
        
        self.stop_button = QPushButton("⏹️ Stop Scan")
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("""
            QPushButton {
                background-color: #5f2d2d;
                border: 2px solid #8f4a4a;
                border-radius: 8px;
                padding: 10px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #7f3d3d;
            }
            QPushButton:pressed {
                background-color: #4f1d1d;
            }
        """)
        self.stop_button.clicked.connect(self.stop_scan)
        
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        # Quick presets
        presets_group = QGroupBox("🎚️ Quick Presets")
        presets_layout = QHBoxLayout(presets_group)
        
        preset_buttons = [
            ("Web App", self.load_webapp_preset),
            ("Windows", self.load_windows_preset),
            ("Linux", self.load_linux_preset),
            ("Generate", self.load_generate_preset)
        ]
        
        for name, callback in preset_buttons:
            btn = QPushButton(name)
            btn.clicked.connect(callback)
            presets_layout.addWidget(btn)
        
        layout.addWidget(presets_group)
        
        return panel
    
    def create_basic_config_group(self) -> QGroupBox:
        """Create basic configuration group"""
        group = QGroupBox("🔧 Basic Configuration")
        layout = QFormLayout(group)
        
        # Module selection
        self.module_combo = QComboBox()
        self.module_combo.addItems([
            "http", "http-url", "ftp", "tftp", "payload", "stdout"
        ])
        self.module_combo.currentTextChanged.connect(self.on_module_changed)
        layout.addRow("Module:", self.module_combo)
        
        # OS Type
        self.os_combo = QComboBox()
        self.os_combo.addItems(["unix", "windows", "generic"])
        layout.addRow("OS Type:", self.os_combo)
        
        # Depth
        self.depth_spin = QSpinBox()
        self.depth_spin.setRange(1, 20)
        self.depth_spin.setValue(6)
        layout.addRow("Depth:", self.depth_spin)
        
        return group
    
    def create_target_config_group(self) -> QGroupBox:
        """Create target configuration group"""
        group = QGroupBox("🎯 Target Configuration")
        layout = QFormLayout(group)
        
        # Host
        self.host_edit = QLineEdit()
        self.host_edit.setPlaceholderText("example.com or 192.168.1.1")
        layout.addRow("Host:", self.host_edit)
        
        # Port
        self.port_spin = QSpinBox()
        self.port_spin.setRange(1, 65535)
        self.port_spin.setValue(80)
        layout.addRow("Port:", self.port_spin)
        
        # Target file
        self.file_edit = QLineEdit()
        self.file_edit.setPlaceholderText("/etc/passwd or boot.ini")
        layout.addRow("Target File:", self.file_edit)
        
        # Target URL (for http-url module)
        self.url_edit = QLineEdit()
        self.url_edit.setPlaceholderText("http://example.com/page.php?file=TRAVERSAL")
        layout.addRow("Target URL:", self.url_edit)
        
        # Pattern
        self.pattern_edit = QLineEdit()
        self.pattern_edit.setPlaceholderText("root: or Administrator")
        layout.addRow("Success Pattern:", self.pattern_edit)
        
        # SSL
        self.ssl_check = QCheckBox("Use SSL/HTTPS")
        layout.addRow("Security:", self.ssl_check)
        
        return group
    
    def create_advanced_config_group(self) -> QGroupBox:
        """Create advanced configuration group"""
        group = QGroupBox("⚙️ Advanced Configuration")
        layout = QFormLayout(group)
        
        # Delay
        self.delay_spin = QSpinBox()
        self.delay_spin.setRange(0, 10000)
        self.delay_spin.setValue(300)
        self.delay_spin.setSuffix(" ms")
        layout.addRow("Delay:", self.delay_spin)
        
        # HTTP Method
        self.method_combo = QComboBox()
        self.method_combo.addItems(["GET", "POST", "HEAD", "PUT", "DELETE", "COPY", "MOVE"])
        layout.addRow("HTTP Method:", self.method_combo)
        
        # User Agent (for HTTP)
        self.user_agent_edit = QLineEdit()
        self.user_agent_edit.setPlaceholderText("Mozilla/5.0 (Custom User Agent)")
        layout.addRow("User Agent:", self.user_agent_edit)
        
        # Payload File (for payload module)
        payload_layout = QHBoxLayout()
        self.payload_edit = QLineEdit()
        self.payload_edit.setPlaceholderText("custom_payloads.txt")
        
        self.payload_browse_button = QPushButton("Browse")
        self.payload_browse_button.clicked.connect(self.browse_payload_file)
        
        payload_layout.addWidget(self.payload_edit)
        payload_layout.addWidget(self.payload_browse_button)
        
        layout.addRow("Payload File:", payload_layout)
        
        # Options
        options_layout = QVBoxLayout()
        
        self.break_first_check = QCheckBox("Break on first hit")
        self.continue_error_check = QCheckBox("Continue on errors")
        self.continue_error_check.setChecked(True)
        self.quiet_check = QCheckBox("Quiet mode")
        self.extra_files_check = QCheckBox("Include extra files")
        
        # Advanced options
        self.os_detection_check = QCheckBox("OS detection (requires nmap)")
        self.service_detection_check = QCheckBox("Service detection/banner grab")
        self.bisection_check = QCheckBox("Bisection algorithm")
        
        options_layout.addWidget(self.break_first_check)
        options_layout.addWidget(self.continue_error_check)
        options_layout.addWidget(self.quiet_check)
        options_layout.addWidget(self.extra_files_check)
        options_layout.addWidget(self.os_detection_check)
        options_layout.addWidget(self.service_detection_check)
        options_layout.addWidget(self.bisection_check)
        
        layout.addRow("Options:", options_layout)
        
        # Extension
        self.extension_edit = QLineEdit()
        self.extension_edit.setPlaceholderText(".txt or .bak")
        layout.addRow("Extension:", self.extension_edit)
        
        return group
    
    def create_auth_config_group(self) -> QGroupBox:
        """Create authentication configuration group"""
        group = QGroupBox("🔐 Authentication")
        layout = QFormLayout(group)
        
        # Username
        self.username_edit = QLineEdit()
        self.username_edit.setPlaceholderText("admin")
        layout.addRow("Username:", self.username_edit)
        
        # Password
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("password")
        layout.addRow("Password:", self.password_edit)
        
        return group
    
    def create_output_config_group(self) -> QGroupBox:
        """Create output configuration group"""
        group = QGroupBox("📄 Output Configuration")
        layout = QFormLayout(group)
        
        # Output format
        self.format_combo = QComboBox()
        self.format_combo.addItems(["text", "json", "csv", "xml", "html"])
        layout.addRow("Format:", self.format_combo)
        
        # Output file
        output_layout = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("report.txt")
        
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_output_file)
        
        output_layout.addWidget(self.output_edit)
        output_layout.addWidget(self.browse_button)
        
        layout.addRow("Output File:", output_layout)
        
        return group
    
    def create_output_panel(self) -> QWidget:
        """Create the output and monitoring panel"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        
        # Create tab widget for different views
        self.tab_widget = QTabWidget()
        
        # Output tab
        output_tab = self.create_output_tab()
        self.tab_widget.addTab(output_tab, qta.icon('fa5s.terminal'), "Output")
        
        # Monitoring tab
        monitoring_tab = self.create_monitoring_tab()
        self.tab_widget.addTab(monitoring_tab, qta.icon('fa5s.chart-line'), "Monitoring")
        
        # History tab
        history_tab = self.create_history_tab()
        self.tab_widget.addTab(history_tab, qta.icon('fa5s.history'), "History")
        
        layout.addWidget(self.tab_widget)
        
        return panel
    
    def create_output_tab(self) -> QWidget:
        """Create the output tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Progress section
        progress_group = QGroupBox("📊 Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready to start scan")
        
        progress_layout.addWidget(self.progress_bar)
        progress_layout.addWidget(self.progress_label)
        
        layout.addWidget(progress_group)
        
        # Output section
        output_group = QGroupBox("📺 Live Output")
        output_layout = QVBoxLayout(output_group)
        
        # Output controls
        controls_layout = QHBoxLayout()
        
        self.clear_output_btn = QPushButton("Clear")
        self.clear_output_btn.setIcon(qta.icon('fa5s.eraser'))
        self.clear_output_btn.clicked.connect(self.clear_output)
        
        self.save_output_btn = QPushButton("Save")
        self.save_output_btn.setIcon(qta.icon('fa5s.save'))
        self.save_output_btn.clicked.connect(self.save_output)
        
        self.auto_scroll_check = QCheckBox("Auto-scroll")
        self.auto_scroll_check.setChecked(True)
        
        controls_layout.addWidget(self.clear_output_btn)
        controls_layout.addWidget(self.save_output_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self.auto_scroll_check)
        
        output_layout.addLayout(controls_layout)
        
        # Output text area
        self.output_text = QPlainTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Consolas", 10))
        
        # Apply syntax highlighting
        self.highlighter = OutputHighlighter(self.output_text.document())
        
        output_layout.addWidget(self.output_text)
        layout.addWidget(output_group)
        
        return tab
    
    def create_monitoring_tab(self) -> QWidget:
        """Create the monitoring tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Resource monitoring
        resource_group = QGroupBox("💻 System Resources")
        resource_layout = QGridLayout(resource_group)
        
        # CPU usage
        resource_layout.addWidget(QLabel("CPU Usage:"), 0, 0)
        self.cpu_progress = QProgressBar()
        self.cpu_label = QLabel("0%")
        resource_layout.addWidget(self.cpu_progress, 0, 1)
        resource_layout.addWidget(self.cpu_label, 0, 2)
        
        # Memory usage
        resource_layout.addWidget(QLabel("Memory Usage:"), 1, 0)
        self.memory_progress = QProgressBar()
        self.memory_label = QLabel("0%")
        resource_layout.addWidget(self.memory_progress, 1, 1)
        resource_layout.addWidget(self.memory_label, 1, 2)
        
        # Process resources
        resource_layout.addWidget(QLabel("Process CPU:"), 2, 0)
        self.process_cpu_progress = QProgressBar()
        self.process_cpu_label = QLabel("0%")
        resource_layout.addWidget(self.process_cpu_progress, 2, 1)
        resource_layout.addWidget(self.process_cpu_label, 2, 2)
        
        resource_layout.addWidget(QLabel("Process Memory:"), 3, 0)
        self.process_memory_label = QLabel("0 MB")
        resource_layout.addWidget(self.process_memory_label, 3, 1, 1, 2)
        
        layout.addWidget(resource_group)
        
        # Performance graphs (if pyqtgraph is available)
        try:
            graph_group = QGroupBox("📈 Performance Graphs")
            graph_layout = QVBoxLayout(graph_group)
            
            self.cpu_graph = pg.PlotWidget(title="CPU Usage Over Time")
            self.cpu_graph.setYRange(0, 100)
            self.cpu_data = []
            self.cpu_curve = self.cpu_graph.plot(pen='g')
            
            graph_layout.addWidget(self.cpu_graph)
            layout.addWidget(graph_group)
            
        except Exception:
            pass
        
        layout.addStretch()
        
        return tab
    
    def create_history_tab(self) -> QWidget:
        """Create the scan history tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # History controls
        controls_layout = QHBoxLayout()
        
        refresh_btn = QPushButton("Refresh")
        refresh_btn.setIcon(qta.icon('fa5s.sync'))
        refresh_btn.clicked.connect(self.refresh_history)
        
        clear_history_btn = QPushButton("Clear History")
        clear_history_btn.setIcon(qta.icon('fa5s.trash'))
        clear_history_btn.clicked.connect(self.clear_history)
        
        controls_layout.addWidget(refresh_btn)
        controls_layout.addWidget(clear_history_btn)
        controls_layout.addStretch()
        
        layout.addLayout(controls_layout)
        
        # History table
        self.history_table = QTableWidget()
        self.history_table.setColumnCount(6)
        self.history_table.setHorizontalHeaderLabels([
            "Timestamp", "Module", "Target", "Status", "Duration", "Results"
        ])
        
        layout.addWidget(self.history_table)
        
        return tab
    
    def init_menubar(self):
        """Initialize the menu bar"""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu("File")
        
        new_action = QAction(qta.icon('fa5s.file'), "New Configuration", self)
        new_action.setShortcut("Ctrl+N")
        new_action.triggered.connect(self.new_configuration)
        file_menu.addAction(new_action)
        
        open_action = QAction(qta.icon('fa5s.folder-open'), "Load Configuration", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.load_configuration)
        file_menu.addAction(open_action)
        
        save_action = QAction(qta.icon('fa5s.save'), "Save Configuration", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_configuration)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction(qta.icon('fa5s.sign-out-alt'), "Exit", self)
        exit_action.setShortcut("Ctrl+Q")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = menubar.addMenu("Tools")
        
        verify_action = QAction(qta.icon('fa5s.check-circle'), "Verify Installation", self)
        verify_action.triggered.connect(self.verify_installation)
        tools_menu.addAction(verify_action)
        
        api_action = QAction(qta.icon('fa5s.server'), "Start API Server", self)
        api_action.triggered.connect(self.start_api_server)
        tools_menu.addAction(api_action)
        
        # Help menu
        help_menu = menubar.addMenu("Help")
        
        about_action = QAction(qta.icon('fa5s.info-circle'), "About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
    
    def init_toolbar(self):
        """Initialize the toolbar"""
        toolbar = self.addToolBar("Main")
        toolbar.setIconSize(QSize(24, 24))
        
        # Quick actions
        start_action = QAction(qta.icon('fa5s.play'), "Start Scan", self)
        start_action.triggered.connect(self.start_scan)
        toolbar.addAction(start_action)
        
        stop_action = QAction(qta.icon('fa5s.stop'), "Stop Scan", self)
        stop_action.triggered.connect(self.stop_scan)
        toolbar.addAction(stop_action)
        
        toolbar.addSeparator()
        
        clear_action = QAction(qta.icon('fa5s.eraser'), "Clear Output", self)
        clear_action.triggered.connect(self.clear_output)
        toolbar.addAction(clear_action)
        
        save_action = QAction(qta.icon('fa5s.save'), "Save Output", self)
        save_action.triggered.connect(self.save_output)
        toolbar.addAction(save_action)
    
    def init_statusbar(self):
        """Initialize the status bar"""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status labels
        self.status_label = QLabel("Ready")
        self.connection_label = QLabel("Disconnected")
        self.scan_count_label = QLabel("Scans: 0")
        
        self.status_bar.addWidget(self.status_label)
        self.status_bar.addPermanentWidget(self.connection_label)
        self.status_bar.addPermanentWidget(self.scan_count_label)
    
    # Event handlers and utility methods
    def on_module_changed(self, module):
        """Handle module selection change"""
        # Update UI based on selected module
        is_stdout = module == "stdout"
        is_http_url = module == "http-url"
        is_payload = module == "payload"
        is_http = module in ["http", "http-url"]
        
        # Enable/disable fields based on module
        self.host_edit.setEnabled(not is_stdout and not is_http_url)
        self.port_spin.setEnabled(not is_stdout)
        self.pattern_edit.setEnabled(not is_stdout)
        self.ssl_check.setEnabled(not is_stdout)
        self.username_edit.setEnabled(not is_stdout)
        self.password_edit.setEnabled(not is_stdout)
        self.method_combo.setEnabled(not is_stdout and is_http)
        self.user_agent_edit.setEnabled(not is_stdout and is_http)
        
        # Show/hide module-specific fields
        self.url_edit.setEnabled(is_http_url)
        self.payload_edit.setEnabled(is_payload)
        self.payload_browse_button.setEnabled(is_payload)
        
        # Update status
        if is_stdout:
            self.status_label.setText("Pattern Generation Mode (STDOUT)")
        elif is_http_url:
            self.status_label.setText("HTTP URL Module - Use target URL field")
        elif is_payload:
            self.status_label.setText("Payload Module - Specify payload file")
        else:
            self.status_label.setText("Scan Mode")
    
    def load_webapp_preset(self):
        """Load web application preset"""
        self.module_combo.setCurrentText("http")
        self.os_combo.setCurrentText("unix")
        self.port_spin.setValue(80)
        self.file_edit.setText("/etc/passwd")
        self.pattern_edit.setText("root:")
        self.depth_spin.setValue(6)
    
    def load_windows_preset(self):
        """Load Windows preset"""
        self.module_combo.setCurrentText("http")
        self.os_combo.setCurrentText("windows")
        self.port_spin.setValue(80)
        self.file_edit.setText("boot.ini")
        self.pattern_edit.setText("Windows")
        self.depth_spin.setValue(8)
    
    def load_linux_preset(self):
        """Load Linux preset"""
        self.module_combo.setCurrentText("http")
        self.os_combo.setCurrentText("unix")
        self.port_spin.setValue(80)
        self.file_edit.setText("/etc/passwd")
        self.pattern_edit.setText("root:")
        self.depth_spin.setValue(6)
    
    def load_generate_preset(self):
        """Load pattern generation preset"""
        self.module_combo.setCurrentText("generate")
        self.os_combo.setCurrentText("unix")
        self.file_edit.setText("/etc/passwd")
        self.depth_spin.setValue(6)
    
    def get_current_config(self) -> ScanConfiguration:
        """Get current configuration from UI"""
        config = ScanConfiguration()
        
        config.module = self.module_combo.currentText()
        config.target_host = self.host_edit.text()
        config.target_port = self.port_spin.value()
        config.target_file = self.file_edit.text()
        config.target_url = self.url_edit.text()
        config.pattern = self.pattern_edit.text()
        config.depth = self.depth_spin.value()
        config.os_type = self.os_combo.currentText()
        config.use_ssl = self.ssl_check.isChecked()
        config.delay = self.delay_spin.value() / 1000.0  # Convert ms to seconds
        config.break_on_first = self.break_first_check.isChecked()
        config.continue_on_error = self.continue_error_check.isChecked()
        config.quiet_mode = self.quiet_check.isChecked()
        config.extra_files = self.extra_files_check.isChecked()
        config.extension = self.extension_edit.text()
        config.username = self.username_edit.text()
        config.password = self.password_edit.text()
        config.http_method = self.method_combo.currentText()
        config.user_agent = self.user_agent_edit.text()
        config.payload_file = self.payload_edit.text()
        config.os_detection = self.os_detection_check.isChecked()
        config.service_detection = self.service_detection_check.isChecked()
        config.bisection = self.bisection_check.isChecked()
        config.output_format = self.format_combo.currentText()
        config.output_file = self.output_edit.text()
        
        return config
    
    def start_scan(self):
        """Start a new scan"""
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Warning", "A scan is already running!")
            return
        
        # Get configuration
        config = self.get_current_config()
        
        # Validate configuration
        if config.module != "generate" and not config.target_host:
            QMessageBox.warning(self, "Warning", "Please enter a target host!")
            return
        
        # Clear output
        self.clear_output()
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setValue(0)
        self.progress_label.setText("Initializing scan...")
        
        # Create and start worker
        self.scan_worker = ScanWorker(config, self.python_cmd, self.script_path)
        self.scan_worker.output_ready.connect(self.append_output)
        self.scan_worker.scan_finished.connect(self.on_scan_finished)
        self.scan_worker.progress_updated.connect(self.update_progress)
        self.scan_worker.scan_started.connect(self.on_scan_started)
        
        self.scan_worker.start()
        
        # Update status
        self.status_label.setText("Scan running...")
        
        # Set process for resource monitoring
        if self.scan_worker.process:
            self.resource_monitor.set_scan_process(self.scan_worker.process)
    
    def stop_scan(self):
        """Stop the running scan"""
        if self.scan_worker:
            self.scan_worker.stop_scan()
            self.status_label.setText("Stopping scan...")
    
    def on_scan_started(self):
        """Handle scan started event"""
        self.connection_label.setText("Connected")
        self.connection_label.setStyleSheet("color: green;")
    
    def on_scan_finished(self, return_code: int, message: str):
        """Handle scan finished event"""
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setValue(100 if return_code == 0 else 0)
        self.progress_label.setText(message)
        
        # Update status
        if return_code == 0:
            self.status_label.setText("Scan completed successfully")
            self.connection_label.setText("Completed")
            self.connection_label.setStyleSheet("color: blue;")
        else:
            self.status_label.setText("Scan failed or stopped")
            self.connection_label.setText("Disconnected")
            self.connection_label.setStyleSheet("color: red;")
        
        # Add to history
        self.add_to_history(return_code == 0)
        
        # Clear process from resource monitor
        self.resource_monitor.set_scan_process(None)
    
    def update_progress(self, value: int, message: str):
        """Update progress display"""
        self.progress_bar.setValue(value)
        self.progress_label.setText(message)
    
    def append_output(self, text: str):
        """Append text to output"""
        self.output_text.appendPlainText(text)
        
        # Auto-scroll if enabled
        if self.auto_scroll_check.isChecked():
            cursor = self.output_text.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            self.output_text.setTextCursor(cursor)
    
    def clear_output(self):
        """Clear the output text"""
        self.output_text.clear()
    
    def save_output(self):
        """Save output to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output", "scan_output.txt", 
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.output_text.toPlainText())
                QMessageBox.information(self, "Success", f"Output saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save output: {str(e)}")
    
    def browse_output_file(self):
        """Browse for output file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Select Output File", "report.txt",
            "Text Files (*.txt);;JSON Files (*.json);;CSV Files (*.csv);;All Files (*)"
        )
        
        if filename:
            self.output_edit.setText(filename)

    def browse_payload_file(self):
        """Browse for payload file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Payload File", "",
            "Text Files (*.txt);;All Files (*)"
        )
        
        if filename:
            self.payload_edit.setText(filename)
    
    def update_resource_display(self, data: dict):
        """Update resource monitoring display"""
        # Update progress bars
        self.cpu_progress.setValue(int(data['cpu_percent']))
        self.cpu_label.setText(f"{data['cpu_percent']:.1f}%")
        
        self.memory_progress.setValue(int(data['memory_percent']))
        self.memory_label.setText(f"{data['memory_percent']:.1f}%")
        
        self.process_cpu_progress.setValue(int(data['process_cpu']))
        self.process_cpu_label.setText(f"{data['process_cpu']:.1f}%")
        
        self.process_memory_label.setText(f"{data['process_memory']} MB")
        
        # Update graphs if available
        try:
            if hasattr(self, 'cpu_graph'):
                self.cpu_data.append(data['cpu_percent'])
                if len(self.cpu_data) > 100:
                    self.cpu_data = self.cpu_data[-100:]
                self.cpu_curve.setData(self.cpu_data)
        except:
            pass
    
    def add_to_history(self, success: bool):
        """Add scan to history"""
        config = self.get_current_config()
        
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'module': config.module,
            'target': config.target_host or 'N/A',
            'status': 'Success' if success else 'Failed',
            'duration': '0:00',  # TODO: Calculate actual duration
            'results': 'N/A'  # TODO: Parse results
        }
        
        self.scan_history.append(history_entry)
        self.refresh_history()
        
        # Update scan count
        self.scan_count_label.setText(f"Scans: {len(self.scan_history)}")
    
    def refresh_history(self):
        """Refresh the history table"""
        self.history_table.setRowCount(len(self.scan_history))
        
        for i, entry in enumerate(self.scan_history):
            self.history_table.setItem(i, 0, QTableWidgetItem(entry['timestamp']))
            self.history_table.setItem(i, 1, QTableWidgetItem(entry['module']))
            self.history_table.setItem(i, 2, QTableWidgetItem(entry['target']))
            self.history_table.setItem(i, 3, QTableWidgetItem(entry['status']))
            self.history_table.setItem(i, 4, QTableWidgetItem(entry['duration']))
            self.history_table.setItem(i, 5, QTableWidgetItem(entry['results']))
    
    def clear_history(self):
        """Clear scan history"""
        reply = QMessageBox.question(
            self, "Confirm", "Are you sure you want to clear the scan history?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.scan_history.clear()
            self.refresh_history()
            self.scan_count_label.setText("Scans: 0")
    
    def new_configuration(self):
        """Create new configuration"""
        # Reset all fields to defaults
        self.module_combo.setCurrentIndex(0)
        self.host_edit.clear()
        self.port_spin.setValue(80)
        self.file_edit.clear()
        self.pattern_edit.clear()
        self.depth_spin.setValue(6)
        self.os_combo.setCurrentIndex(0)
        # ... reset other fields
    
    def load_configuration(self):
        """Load configuration from file"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Load Configuration", "", 
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    config_data = json.load(f)
                
                # Apply configuration to UI
                # TODO: Implement configuration loading
                
                QMessageBox.information(self, "Success", "Configuration loaded successfully")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to load configuration: {str(e)}")
    
    def save_configuration(self):
        """Save current configuration to file"""
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Configuration", "config.json",
            "JSON Files (*.json);;All Files (*)"
        )
        
        if filename:
            try:
                config = self.get_current_config()
                config_data = {
                    'module': config.module,
                    'target_host': config.target_host,
                    'target_port': config.target_port,
                    'target_file': config.target_file,
                    'pattern': config.pattern,
                    'depth': config.depth,
                    'os_type': config.os_type,
                    'use_ssl': config.use_ssl,
                    'delay': config.delay,
                    'break_on_first': config.break_on_first,
                    'continue_on_error': config.continue_on_error,
                    'quiet_mode': config.quiet_mode,
                    'extra_files': config.extra_files,
                    'extension': config.extension,
                    'username': config.username,
                    'password': config.password,
                    'http_method': config.http_method,
                    'output_format': config.output_format,
                    'output_file': config.output_file
                }
                
                with open(filename, 'w') as f:
                    json.dump(config_data, f, indent=2)
                
                QMessageBox.information(self, "Success", f"Configuration saved to {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save configuration: {str(e)}")
    
    def verify_installation(self):
        """Verify DotDotPwn installation"""
        try:
            # Run verification script
            result = subprocess.run(
                [self.python_cmd, str(self.project_root / "comprehensive_verification.py")],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                QMessageBox.information(self, "Verification", "Installation verified successfully!")
            else:
                QMessageBox.warning(self, "Verification", f"Verification failed:\n{result.stderr}")
                
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Verification error: {str(e)}")
    
    def start_api_server(self):
        """Start the API server"""
        try:
            # TODO: Implement API server startup
            QMessageBox.information(self, "API Server", "API server functionality coming soon!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start API server: {str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """
        <h2>DotDotPwn GUI</h2>
        <p><b>Version:</b> 3.0.2</p>
        <p><b>Description:</b> A comprehensive directory traversal fuzzer with GUI interface</p>
        <p><b>Original Authors:</b> chr1x & nitr0us</p>
        <p><b>Python Implementation:</b> AI Assistant</p>
        <p><b>GUI Framework:</b> PyQt6</p>
        
        <p>This tool is designed for authorized security testing only.</p>
        <p>Users are responsible for compliance with applicable laws and regulations.</p>
        """
        
        QMessageBox.about(self, "About DotDotPwn GUI", about_text)
    
    def load_settings(self):
        """Load application settings"""
        # Window geometry
        geometry = self.settings.value("geometry")
        if geometry:
            self.restoreGeometry(geometry)
        
        # Window state
        state = self.settings.value("windowState")
        if state:
            self.restoreState(state)
    
    def save_settings(self):
        """Save application settings"""
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
    
    def closeEvent(self, event):
        """Handle application close event"""
        # Stop any running scans
        if self.scan_worker and self.scan_worker.isRunning():
            reply = QMessageBox.question(
                self, "Confirm Exit", 
                "A scan is currently running. Do you want to stop it and exit?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            
            if reply == QMessageBox.StandardButton.Yes:
                self.scan_worker.stop_scan()
                self.scan_worker.wait(5000)  # Wait up to 5 seconds
            else:
                event.ignore()
                return
        
        # Stop resource monitoring
        self.resource_monitor.stop()
        self.resource_monitor.wait(2000)
        
        # Save settings
        self.save_settings()
        
        event.accept()


def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    
    # Set application properties
    app.setApplicationName("DotDotPwn GUI")
    app.setApplicationVersion("3.0.2")
    app.setOrganizationName("DotDotPwn")
    app.setOrganizationDomain("dotdotpwn.com")
    
    # Create and show main window
    window = DotDotPwnGUI()
    window.show()
    
    # Run application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()