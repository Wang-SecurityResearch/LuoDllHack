# -*- coding: utf-8 -*-
"""
LuoDllHack Cutter Plugin - 漏洞深度分析与验证

在 Cutter 中集成 LuoDllHack 漏洞分析能力：
- 危险 API 扫描
- 污点分析
- 边界检查验证
- 符号执行验证

安装方法：
1. 将此文件复制到 Cutter 插件目录
   - Windows: %APPDATA%/rizin/cutter/plugins/python/
   - Linux: ~/.local/share/rizin/cutter/plugins/python/
2. 确保 luodllhack 包在 Python 路径中
3. 重启 Cutter

使用方法：
- 菜单: Plugins -> LuoDllHack -> Scan Dangerous APIs
- 右键函数: LuoDllHack -> Verify Vulnerability
- 右键地址: LuoDllHack -> Deep Verify
"""

import cutter
from PySide2.QtWidgets import (
    QAction, QMenu, QDockWidget, QWidget, QVBoxLayout,
    QTableWidget, QTableWidgetItem, QHeaderView, QPushButton,
    QLabel, QProgressBar, QTextEdit, QHBoxLayout, QMessageBox,
    QComboBox, QGroupBox, QSplitter
)
from PySide2.QtCore import Qt, QThread, Signal
from PySide2.QtGui import QColor, QBrush

import sys
import os

# 添加 LuoDllHack 路径
LUODLLHACK_PATH = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if LUODLLHACK_PATH not in sys.path:
    sys.path.insert(0, LUODLLHACK_PATH)


# =============================================================================
# 分析工作线程
# =============================================================================

class AnalysisThread(QThread):
    """后台分析线程"""
    progress = Signal(int, str)  # 进度, 消息
    finding = Signal(dict)       # 发现
    finished = Signal(list)      # 完成, 所有发现
    error = Signal(str)          # 错误

    def __init__(self, binary_path, analysis_type="full", target_address=None):
        super().__init__()
        self.binary_path = binary_path
        self.analysis_type = analysis_type
        self.target_address = target_address
        self._findings = []

    def run(self):
        try:
            from luodllhack.core import RizinCore
            from luodllhack.analysis.taint import TaintEngine

            self.progress.emit(10, "Initializing analysis engine...")

            # 使用 Cutter 的 Rizin 实例
            rz = RizinCore(self.binary_path)

            self.progress.emit(20, "Creating taint engine...")
            engine = TaintEngine(rz)

            if self.analysis_type == "dangerous_api":
                self._scan_dangerous_apis(engine)
            elif self.analysis_type == "verify":
                self._verify_address(engine, self.target_address)
            elif self.analysis_type == "full":
                self._full_analysis(engine)

            self.progress.emit(100, "Analysis complete")
            self.finished.emit(self._findings)

        except Exception as e:
            import traceback
            self.error.emit(f"Analysis failed: {e}\n{traceback.format_exc()}")

    def _scan_dangerous_apis(self, engine):
        """扫描危险 API"""
        self.progress.emit(30, "Scanning dangerous API imports...")

        # 获取危险 API
        dangerous_apis = engine.get_dangerous_imports()

        for i, (addr, api_info) in enumerate(dangerous_apis.items()):
            progress = 30 + int(60 * i / max(len(dangerous_apis), 1))
            self.progress.emit(progress, f"Analyzing {api_info.get('name', 'unknown')}...")

            finding = {
                "address": addr,
                "type": "dangerous_api",
                "api_name": api_info.get("name", "unknown"),
                "vuln_type": api_info.get("vuln_type", "UNKNOWN"),
                "severity": api_info.get("severity", "Medium"),
                "confidence": 0.35,
                "status": "detected",
                "evidence": [f"Dangerous API import: {api_info.get('name')}"],
            }
            self._findings.append(finding)
            self.finding.emit(finding)

    def _verify_address(self, engine, address):
        """验证特定地址"""
        self.progress.emit(30, f"Verifying address 0x{address:x}...")

        # 边界检查分析
        self.progress.emit(50, "Checking bounds...")
        bounds_result = self._check_bounds(engine, address)

        # 污点分析
        self.progress.emit(70, "Taint analysis...")
        taint_result = engine.analyze_address(address)

        # 计算置信度
        confidence = 0.4
        evidence = []

        if bounds_result.get("has_bounds_check"):
            confidence -= 0.15
            evidence.append("Bounds check found")
        else:
            confidence += 0.2
            evidence.append("No bounds check detected")

        if taint_result.get("tainted"):
            confidence += 0.2
            evidence.append(f"Tainted from: {taint_result.get('source', 'unknown')}")

        finding = {
            "address": address,
            "type": "verified",
            "vuln_type": taint_result.get("vuln_type", "POTENTIAL"),
            "severity": "High" if confidence > 0.6 else "Medium",
            "confidence": min(confidence, 1.0),
            "status": "verified" if confidence > 0.5 else "low_confidence",
            "evidence": evidence,
            "bounds_check": bounds_result,
        }
        self._findings.append(finding)
        self.finding.emit(finding)

    def _check_bounds(self, engine, address):
        """检查边界检查"""
        try:
            # 获取函数
            func = engine.rz.get_function_containing(address)
            if not func:
                return {"has_bounds_check": False, "note": "No containing function"}

            # 分析边界检查模式
            bounds_check_mnemonics = {'cmp', 'test'}
            conditional_jumps = {'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle'}

            has_check = False
            for bb in func.blocks:
                for i, insn in enumerate(bb.instructions):
                    if insn.address >= address:
                        break
                    if insn.mnemonic.lower() in bounds_check_mnemonics:
                        # 检查后续指令
                        for j in range(i + 1, min(i + 5, len(bb.instructions))):
                            if bb.instructions[j].mnemonic.lower() in conditional_jumps:
                                has_check = True
                                break

            return {"has_bounds_check": has_check}
        except Exception as e:
            return {"has_bounds_check": False, "error": str(e)}

    def _full_analysis(self, engine):
        """完整分析"""
        self._scan_dangerous_apis(engine)

        # 对每个发现进行深度验证
        for i, finding in enumerate(self._findings[:]):
            if finding.get("address"):
                self.progress.emit(
                    60 + int(30 * i / max(len(self._findings), 1)),
                    f"Deep verifying 0x{finding['address']:x}..."
                )
                self._verify_address(engine, finding["address"])


# =============================================================================
# 发现表格 Widget
# =============================================================================

class FindingsTableWidget(QTableWidget):
    """漏洞发现表格"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setColumnCount(6)
        self.setHorizontalHeaderLabels([
            "Address", "Type", "Severity", "Confidence", "Status", "API/Details"
        ])
        self.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setAlternatingRowColors(True)
        self.cellDoubleClicked.connect(self._on_double_click)

    def add_finding(self, finding):
        """添加发现"""
        row = self.rowCount()
        self.insertRow(row)

        addr = finding.get("address", 0)
        self.setItem(row, 0, QTableWidgetItem(f"0x{addr:x}"))
        self.setItem(row, 1, QTableWidgetItem(finding.get("vuln_type", "UNKNOWN")))

        severity = finding.get("severity", "Medium")
        severity_item = QTableWidgetItem(severity)
        if severity == "Critical":
            severity_item.setBackground(QBrush(QColor(255, 0, 0, 100)))
        elif severity == "High":
            severity_item.setBackground(QBrush(QColor(255, 165, 0, 100)))
        elif severity == "Medium":
            severity_item.setBackground(QBrush(QColor(255, 255, 0, 100)))
        self.setItem(row, 2, severity_item)

        confidence = finding.get("confidence", 0)
        conf_item = QTableWidgetItem(f"{confidence:.0%}")
        if confidence >= 0.7:
            conf_item.setBackground(QBrush(QColor(0, 255, 0, 100)))
        elif confidence >= 0.5:
            conf_item.setBackground(QBrush(QColor(255, 255, 0, 100)))
        else:
            conf_item.setBackground(QBrush(QColor(255, 0, 0, 50)))
        self.setItem(row, 3, conf_item)

        self.setItem(row, 4, QTableWidgetItem(finding.get("status", "detected")))
        self.setItem(row, 5, QTableWidgetItem(
            finding.get("api_name", "") or ", ".join(finding.get("evidence", [])[:2])
        ))

        # 存储完整数据
        self.item(row, 0).setData(Qt.UserRole, finding)

    def _on_double_click(self, row, col):
        """双击跳转到地址"""
        item = self.item(row, 0)
        if item:
            finding = item.data(Qt.UserRole)
            if finding and finding.get("address"):
                cutter.cmd(f"s 0x{finding['address']:x}")

    def clear_findings(self):
        """清空"""
        self.setRowCount(0)


# =============================================================================
# 主 Dock Widget
# =============================================================================

class LuoDllHackDockWidget(cutter.CutterDockWidget):
    """LuoDllHack 分析面板"""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("LuoDllHackAnalysis")
        self.setWindowTitle("LuoDllHack Vulnerability Analysis")

        self._thread = None
        self._setup_ui()

    def _setup_ui(self):
        """设置 UI"""
        main_widget = QWidget()
        layout = QVBoxLayout(main_widget)

        # 控制面板
        control_group = QGroupBox("Analysis Control")
        control_layout = QHBoxLayout(control_group)

        self.analysis_type = QComboBox()
        self.analysis_type.addItems([
            "Full Analysis",
            "Dangerous APIs Only",
            "Verify Current Function"
        ])
        control_layout.addWidget(QLabel("Mode:"))
        control_layout.addWidget(self.analysis_type)

        self.scan_btn = QPushButton("Start Analysis")
        self.scan_btn.clicked.connect(self._start_analysis)
        control_layout.addWidget(self.scan_btn)

        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop_analysis)
        control_layout.addWidget(self.stop_btn)

        layout.addWidget(control_group)

        # 进度条
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat("%p% - %v")
        layout.addWidget(self.progress)

        self.status_label = QLabel("Ready")
        layout.addWidget(self.status_label)

        # 分割器
        splitter = QSplitter(Qt.Vertical)

        # 发现表格
        self.findings_table = FindingsTableWidget()
        splitter.addWidget(self.findings_table)

        # 详情面板
        details_group = QGroupBox("Finding Details")
        details_layout = QVBoxLayout(details_group)
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        splitter.addWidget(details_group)

        splitter.setSizes([300, 150])
        layout.addWidget(splitter)

        # 连接表格选择
        self.findings_table.itemSelectionChanged.connect(self._show_details)

        self.setWidget(main_widget)

    def _start_analysis(self):
        """开始分析"""
        binary_path = cutter.cmdj("ij").get("core", {}).get("file", "")
        if not binary_path:
            QMessageBox.warning(self, "Error", "No binary loaded")
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.findings_table.clear_findings()
        self.progress.setValue(0)

        # 确定分析类型
        mode_map = {
            0: "full",
            1: "dangerous_api",
            2: "verify"
        }
        analysis_type = mode_map.get(self.analysis_type.currentIndex(), "full")

        # 获取当前地址（用于 verify 模式）
        target_address = None
        if analysis_type == "verify":
            target_address = cutter.cmdj("sj")  # 当前地址

        # 启动线程
        self._thread = AnalysisThread(binary_path, analysis_type, target_address)
        self._thread.progress.connect(self._on_progress)
        self._thread.finding.connect(self._on_finding)
        self._thread.finished.connect(self._on_finished)
        self._thread.error.connect(self._on_error)
        self._thread.start()

    def _stop_analysis(self):
        """停止分析"""
        if self._thread and self._thread.isRunning():
            self._thread.terminate()
            self._thread.wait()
        self._on_finished([])

    def _on_progress(self, value, message):
        """进度更新"""
        self.progress.setValue(value)
        self.status_label.setText(message)

    def _on_finding(self, finding):
        """收到发现"""
        self.findings_table.add_finding(finding)

    def _on_finished(self, findings):
        """分析完成"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText(f"Complete - {len(findings)} findings")

        # 添加注释到 Cutter
        for finding in findings:
            addr = finding.get("address", 0)
            if addr:
                comment = f"[LuoDllHack] {finding.get('vuln_type', 'VULN')} " \
                          f"({finding.get('confidence', 0):.0%})"
                cutter.cmd(f"CC {comment} @ 0x{addr:x}")

    def _on_error(self, error_msg):
        """错误"""
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Error")
        QMessageBox.critical(self, "Analysis Error", error_msg)

    def _show_details(self):
        """显示详情"""
        items = self.findings_table.selectedItems()
        if not items:
            return

        row = items[0].row()
        finding = self.findings_table.item(row, 0).data(Qt.UserRole)
        if not finding:
            return

        details = f"""Address: 0x{finding.get('address', 0):x}
Type: {finding.get('vuln_type', 'UNKNOWN')}
Severity: {finding.get('severity', 'Medium')}
Confidence: {finding.get('confidence', 0):.1%}
Status: {finding.get('status', 'detected')}

Evidence:
"""
        for ev in finding.get("evidence", []):
            details += f"  - {ev}\n"

        if finding.get("bounds_check"):
            bc = finding["bounds_check"]
            details += f"\nBounds Check: {'Yes' if bc.get('has_bounds_check') else 'No'}"

        self.details_text.setText(details)


# =============================================================================
# 右键菜单 Actions
# =============================================================================

class LuoDllHackContextMenu(cutter.CutterPlugin):
    """LuoDllHack 右键菜单"""

    name = "LuoDllHack"
    description = "Vulnerability analysis and verification"
    version = "1.0"
    author = "LuoDllHack Team"

    def setupPlugin(self):
        pass

    def setupInterface(self, main):
        # 添加 Dock Widget
        self.dock = LuoDllHackDockWidget(main)
        main.addPluginDockWidget(self.dock)

        # 添加菜单
        self._setup_menus(main)

    def _setup_menus(self, main):
        """设置菜单"""
        # 主菜单
        luodllhack_menu = main.addMenu("LuoDllHack")

        # 扫描危险 API
        scan_action = QAction("Scan Dangerous APIs", main)
        scan_action.triggered.connect(lambda: self._scan_apis())
        luodllhack_menu.addAction(scan_action)

        # 分析当前函数
        analyze_func_action = QAction("Analyze Current Function", main)
        analyze_func_action.triggered.connect(lambda: self._analyze_function())
        luodllhack_menu.addAction(analyze_func_action)

        luodllhack_menu.addSeparator()

        # 显示面板
        show_panel_action = QAction("Show Analysis Panel", main)
        show_panel_action.triggered.connect(lambda: self.dock.show())
        luodllhack_menu.addAction(show_panel_action)

    def _scan_apis(self):
        """扫描危险 API"""
        self.dock.analysis_type.setCurrentIndex(1)
        self.dock._start_analysis()
        self.dock.show()

    def _analyze_function(self):
        """分析当前函数"""
        self.dock.analysis_type.setCurrentIndex(2)
        self.dock._start_analysis()
        self.dock.show()

    def terminate(self):
        pass


# =============================================================================
# 插件注册
# =============================================================================

def create_cutter_plugin():
    return LuoDllHackContextMenu()
