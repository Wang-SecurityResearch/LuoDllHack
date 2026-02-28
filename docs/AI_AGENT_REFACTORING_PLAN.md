# LuoDllHack AI Agent 架构整改路径

## 综合问题诊断

### 核心矛盾图谱

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        架构核心矛盾                                      │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────┐      竞争关系      ┌──────────────┐                   │
│  │ Orchestrator │ ◄──────────────► │  MessageBus  │                   │
│  │  (中心化)     │                   │  (去中心化)   │                   │
│  └──────┬───────┘                   └──────┬───────┘                   │
│         │                                   │                           │
│         │ 直接调用                          │ 发布订阅                   │
│         ▼                                   ▼                           │
│  ┌──────────────┐                   ┌──────────────┐                   │
│  │ParallelExec  │                   │  broadcast   │                   │
│  │.wait_for_all │                   │  _finding()  │                   │
│  └──────────────┘                   └──────────────┘                   │
│         │                                   │                           │
│         └───────────┬───────────────────────┘                           │
│                     ▼                                                   │
│              ┌──────────────┐                                           │
│              │ SharedState  │  ◄── 全局锁瓶颈                           │
│              │ (RLock)      │                                           │
│              └──────────────┘                                           │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 问题严重性矩阵

| 问题 | 影响范围 | 修复复杂度 | 优先级 |
|------|---------|-----------|--------|
| **agent.py 巨型文件 (3800+ 行)** | 可维护性 | 高 | **P0** |
| **Orchestrator/MessageBus 双轨制** | 数据一致性 | 高 | **P0** |
| **SharedState 锁粒度** | 性能/并发 | 中 | **P1** |
| **工作流阶段僵化** | 灵活性 | 中 | **P1** |
| **VerifierAgent/ValidatorAgent 重叠** | 效率 | 中 | **P1** |
| **数据源不同步** (scored_findings) | 报告准确性 | 低 | **P1** (已修复) |
| **记忆系统有效性** | AI能力 | 高 | **P2** |
| **类型提示不一致** | 可维护性 | 低 | **P2** |
| **错误处理泛化** | 可靠性 | 低 | **P2** |

---

## 整改路径总览

### Phase 1: 解耦与拆分 (2-3 周)
**目标**: 消除 God Object，建立清晰的模块边界

### Phase 2: 统一通信模型 (1-2 周)
**目标**: 解决 Orchestrator/MessageBus 双轨制问题

### Phase 3: 状态管理优化 (1-2 周)
**目标**: 改进 SharedState 锁粒度和数据一致性

### Phase 4: 工作流重构 (2 周)
**目标**: 从线性阶段驱动改为任务池驱动

### Phase 5: Agent 能力整合 (1 周)
**目标**: 合并 VerifierAgent/ValidatorAgent，建立反馈循环

### Phase 6: 增强与优化 (持续)
**目标**: 记忆系统、类型提示、错误处理

---

## Phase 1: 解耦与拆分

### 1.1 agent.py 拆分方案

**当前问题**:
- 3800+ 行代码，职责混杂
- 工具注册、ReAct循环、Token管理、多Agent编排全部耦合
- 50+ 行的条件导入 (HAVE_* flags)

**目标结构**:

```
luodllhack/ai/
├── __init__.py              # 公共导出
├── factory.py               # Agent/Orchestrator 工厂 (NEW)
├── hunting.py               # VulnHuntingAgent 核心逻辑 (从agent.py拆出)
├── tools/                   # 工具模块 (NEW)
│   ├── __init__.py
│   ├── registry.py          # ToolRegistry (从agent.py拆出)
│   ├── definitions.py       # 工具定义
│   └── executors.py         # 工具执行器
├── react/                   # ReAct 循环 (NEW)
│   ├── __init__.py
│   ├── loop.py              # ReAct 主循环
│   ├── parser.py            # 响应解析
│   └── token_manager.py     # Token 管理
├── report/                  # 报告生成 (NEW)
│   ├── __init__.py
│   ├── generator.py         # 报告生成
│   └── formatter.py         # 格式化输出
└── agents/                  # 多Agent框架 (保留)
    └── ...
```

**拆分步骤**:

```python
# Step 1: 提取 ToolRegistry (约 800 行)
# 从 agent.py:200-1000 提取到 tools/registry.py

# Step 2: 提取 ReAct 循环 (约 600 行)
# 从 agent.py:2500-3100 提取到 react/loop.py

# Step 3: 提取报告生成 (约 300 行)
# 从 agent.py:3700-4000 提取到 report/generator.py

# Step 4: 保留 VulnHuntingAgent 作为门面 (约 500 行)
# agent.py 精简为入口和协调逻辑
```

### 1.2 条件导入清理

**当前问题**:
```python
# agent.py:50-180 存在大量条件导入
HAVE_GENAI = False
HAVE_VULN_ANALYSIS = False
HAVE_MULTI_BACKEND = False
# ... 20+ 个标志
```

**解决方案**:

```python
# 新建 luodllhack/ai/compat.py
"""依赖兼容性检查模块"""

from dataclasses import dataclass
from typing import Optional, Type

@dataclass
class DependencyStatus:
    genai: bool = False
    vuln_analysis: bool = False
    multi_backend: bool = False
    angr: bool = False
    # ...

    @classmethod
    def detect(cls) -> 'DependencyStatus':
        status = cls()
        try:
            import google.generativeai
            status.genai = True
        except ImportError:
            pass
        # ... 其他检测
        return status

# 全局单例
DEPS = DependencyStatus.detect()

# 使用方式
from luodllhack.ai.compat import DEPS
if DEPS.genai:
    from google.generativeai import ...
```

---

## Phase 2: 统一通信模型

### 2.1 当前双轨制问题

```
路径1: Orchestrator → ParallelExecutor → Agent.process_task() [同步]
路径2: Agent → MessageBus.publish() → Orchestrator._handle_message() [异步]

问题:
- 任务执行走路径1，结果报告走路径2
- 两条路径可能产生竞态
- MessageBus 变成"装饰品"
```

### 2.2 方案选择

**方案 A: 强化 MessageBus (推荐)**

```python
# 移除 Orchestrator 对 Agent.process_task 的直接调用
# 所有交互通过 MessageBus

class Orchestrator:
    def submit_tasks(self, tasks: List[TaskAssignment]) -> None:
        for task in tasks:
            # 通过消息总线发送任务
            self._message_bus.publish(Message(
                msg_type=MessageType.TASK,
                sender="orchestrator",
                receiver=self._select_agent_for_task(task).agent_id,
                payload={"task": task.to_dict()}
            ))

    def _handle_message(self, message: Message) -> None:
        if message.msg_type == MessageType.RESULT:
            # 处理结果
            self._process_agent_result(message.payload["result"])
        elif message.msg_type == MessageType.TASK_CLAIMED:
            # Agent 确认接收任务
            self._update_task_status(message.payload["task_id"], "claimed")

class BaseAgent:
    def _message_handler(self, message: Message) -> None:
        if message.msg_type == MessageType.TASK:
            # 接收并处理任务
            task = TaskAssignment.from_dict(message.payload["task"])
            result = self.process_task(task)
            # 通过消息总线返回结果
            self._message_bus.publish(Message(
                msg_type=MessageType.RESULT,
                sender=self.agent_id,
                receiver="orchestrator",
                payload={"result": result.to_dict()}
            ))
```

**方案 B: 移除 MessageBus (简化)**

```python
# 如果真正的异步协作需求不强，直接移除 MessageBus
# 保持当前的同步调用模式，但优化接口

class Orchestrator:
    def collect_results(self) -> Dict[str, AgentResult]:
        # 保持同步等待
        return self._executor.wait_for_all()

    # 移除所有 MessageBus 相关代码
    # 发现广播改为直接写入 SharedState
```

**推荐**: 方案 A，因为长期来看异步协作更有价值

### 2.3 MessageBus 增强

```python
# message_bus.py 增强

class MessageBus:
    def __init__(self):
        self._pending_acks: Dict[str, asyncio.Event] = {}

    def publish_with_ack(
        self,
        message: Message,
        timeout: float = 5.0
    ) -> bool:
        """发送消息并等待确认"""
        ack_event = asyncio.Event()
        self._pending_acks[message.message_id] = ack_event

        self.publish(message)

        try:
            return ack_event.wait(timeout=timeout)
        finally:
            del self._pending_acks[message.message_id]

    def acknowledge(self, message_id: str) -> None:
        """确认消息已处理"""
        if message_id in self._pending_acks:
            self._pending_acks[message_id].set()
```

---

## Phase 3: 状态管理优化

### 3.1 SharedState 锁粒度改进

**当前问题**:
```python
class SharedState:
    _lock = threading.RLock()  # 全局锁

    def add_finding(self, finding):
        with self._lock:  # 写锁
            # ...

    def get_finding(self, finding_id):
        with self._lock:  # 读也要锁
            # ...
```

**改进方案: 读写锁分离**

```python
import threading
from contextlib import contextmanager

class SharedState:
    def __init__(self):
        self._read_lock = threading.RLock()
        self._write_lock = threading.RLock()
        self._readers = 0

        # 分离不同类型的状态
        self._findings: Dict[str, Finding] = {}
        self._context: AnalysisContext = None
        self._task_state: TaskState = TaskState()

    @contextmanager
    def read_lock(self):
        """读锁 - 允许多读"""
        with self._read_lock:
            self._readers += 1
        try:
            yield
        finally:
            with self._read_lock:
                self._readers -= 1

    @contextmanager
    def write_lock(self):
        """写锁 - 独占"""
        with self._write_lock:
            # 等待所有读者完成
            while self._readers > 0:
                time.sleep(0.001)
            yield

    def get_finding(self, finding_id: str) -> Optional[Finding]:
        with self.read_lock():
            return self._findings.get(finding_id)

    def add_finding(self, finding: Finding) -> bool:
        with self.write_lock():
            # 写操作
            ...
```

### 3.2 快照机制改进

**问题**: LLM 处理期间 SharedState 可能变化

```python
class SharedState:
    def get_snapshot(self, version: bool = True) -> StateSnapshot:
        """获取带版本号的快照"""
        with self.read_lock():
            snapshot = StateSnapshot(
                version=self._version,
                findings=copy.deepcopy(self._findings),
                context=copy.deepcopy(self._context),
                timestamp=time.time()
            )
        return snapshot

    def apply_if_unchanged(
        self,
        snapshot_version: int,
        updates: Dict[str, Any]
    ) -> bool:
        """乐观锁更新 - 如果版本未变则应用更新"""
        with self.write_lock():
            if self._version != snapshot_version:
                return False  # 版本已变，拒绝更新

            # 应用更新
            for finding_id, update in updates.items():
                if finding_id in self._findings:
                    self._findings[finding_id].update(update)

            self._version += 1
            return True
```

---

## Phase 4: 工作流重构

### 4.1 从阶段驱动到任务池驱动

**当前问题**:
```python
# 严格线性阶段
class WorkflowPhase(Enum):
    DISCOVERY = 1
    VERIFICATION = 2
    EXPLOITATION = 3
    VALIDATION = 4
    REVIEW = 5
```

**改进方案: 基于黑板模式的动态触发**

```python
from dataclasses import dataclass
from typing import Callable, List

@dataclass
class TaskTrigger:
    """任务触发条件"""
    name: str
    condition: Callable[[SharedState], bool]
    task_generator: Callable[[SharedState], List[TaskAssignment]]
    priority: int = 5
    cooldown: float = 0.0  # 触发后的冷却时间

class DynamicWorkflow:
    """动态工作流引擎"""

    def __init__(self):
        self._triggers: List[TaskTrigger] = []
        self._last_trigger_time: Dict[str, float] = {}

    def register_trigger(self, trigger: TaskTrigger) -> None:
        self._triggers.append(trigger)
        self._triggers.sort(key=lambda t: t.priority, reverse=True)

    def evaluate(self, state: SharedState) -> List[TaskAssignment]:
        """评估所有触发条件，返回需要执行的任务"""
        tasks = []
        current_time = time.time()

        for trigger in self._triggers:
            # 检查冷却
            last_time = self._last_trigger_time.get(trigger.name, 0)
            if current_time - last_time < trigger.cooldown:
                continue

            # 检查条件
            if trigger.condition(state):
                new_tasks = trigger.task_generator(state)
                tasks.extend(new_tasks)
                self._last_trigger_time[trigger.name] = current_time

        return tasks

# 使用示例
workflow = DynamicWorkflow()

# 触发器: 有未验证的发现 → 生成验证任务
workflow.register_trigger(TaskTrigger(
    name="verify_pending_findings",
    condition=lambda s: any(f.status == "detected" for f in s.get_all_findings()),
    task_generator=lambda s: [
        TaskAssignment(
            task_type="deep_verify",
            parameters={"finding_id": f.finding_id}
        )
        for f in s.get_all_findings() if f.status == "detected"
    ],
    priority=8,
    cooldown=5.0
))

# 触发器: 验证失败次数过多 → 回退到重新发现
workflow.register_trigger(TaskTrigger(
    name="rediscover_on_failure",
    condition=lambda s: s.get_context().verification_failures > 3,
    task_generator=lambda s: [
        TaskAssignment(task_type="rescan_with_relaxed_threshold")
    ],
    priority=6
))
```

### 4.2 阶段转换条件增强

```python
class PhaseTransitionRules:
    """阶段转换规则引擎"""

    @staticmethod
    def can_transition_to_exploitation(state: SharedState) -> bool:
        findings = state.get_all_findings()

        # 条件1: 至少有一个已验证的发现
        verified = [f for f in findings if f.status == "verified"]
        if not verified:
            return False

        # 条件2: 没有进行中的验证任务
        if state.has_pending_tasks(task_type="deep_verify"):
            return False

        # 条件3: 验证成功率 > 10% (避免全是误报)
        detected = [f for f in findings if f.status in ("detected", "verified", "rejected")]
        if detected:
            success_rate = len(verified) / len(detected)
            if success_rate < 0.1:
                logger.warning(f"Low verification success rate: {success_rate:.1%}")
                # 可以继续但记录警告

        return True
```

---

## Phase 5: Agent 能力整合

### 5.1 合并 VerifierAgent 和 ValidatorAgent

**当前重叠**:
- VerifierAgent: 静态验证、边界检查、可达性分析
- ValidatorAgent: 动态验证、沙箱执行、崩溃分析

**合并方案**:

```python
class ValidationAgent(BaseAgent):
    """统一验证Agent - 整合静态和动态验证"""

    agent_id = "validator"
    capabilities = [AgentCapability.VERIFICATION, AgentCapability.VALIDATION]

    def __init__(self, ...):
        super().__init__(...)
        self._task_handlers = {
            # 静态验证 (原 VerifierAgent)
            "static_verify": self._static_verify,
            "check_bounds": self._check_bounds,
            "verify_reachability": self._verify_reachability,

            # 动态验证 (原 ValidatorAgent)
            "dynamic_verify": self._dynamic_verify,
            "sandbox_execute": self._sandbox_execute,
            "analyze_crash": self._analyze_crash,

            # 新增: 组合验证
            "full_verify": self._full_verify,
        }

    def _full_verify(self, task: TaskAssignment) -> AgentResult:
        """完整验证流程: 静态 → 动态"""
        finding_id = task.parameters["finding_id"]

        # Step 1: 静态验证
        static_result = self._static_verify(TaskAssignment(
            task_type="static_verify",
            parameters={"finding_id": finding_id}
        ))

        if not static_result.success:
            return static_result

        # Step 2: 如果有 PoC，进行动态验证
        finding = self.shared_state.get_finding(finding_id)
        if finding.poc_code:
            dynamic_result = self._dynamic_verify(TaskAssignment(
                task_type="dynamic_verify",
                parameters={"finding_id": finding_id}
            ))
            return dynamic_result

        return static_result
```

### 5.2 建立反馈循环

```python
class ValidationAgent(BaseAgent):
    def _dynamic_verify(self, task: TaskAssignment) -> AgentResult:
        finding_id = task.parameters["finding_id"]
        finding = self.shared_state.get_finding(finding_id)

        # 执行 PoC
        exec_result = self.call_tool("execute_poc", {
            "poc_code": finding.poc_code,
            "timeout": 30
        })

        if exec_result.success:
            # 验证成功
            self.shared_state.update_finding(finding_id, status="validated")
            return AgentResult(success=True, ...)
        else:
            # 验证失败 - 生成反馈任务给 ExploiterAgent
            result = AgentResult(success=False, ...)

            # 反馈循环: 请求改进 PoC
            result.add_next_task(TaskAssignment(
                task_type="improve_poc",
                parameters={
                    "finding_id": finding_id,
                    "failure_reason": exec_result.error,
                    "crash_info": self._analyze_crash_info(exec_result),
                    "previous_poc": finding.poc_code,
                    "attempt": task.parameters.get("attempt", 0) + 1
                },
                priority=8,  # 高优先级
                max_attempts=3  # 限制重试次数
            ))

            return result
```

---

## Phase 6: 增强与优化

### 6.1 记忆系统升级

**当前问题**: 简单的 JSON 文件 + 特征匹配

**升级方案**:

```python
# 可选: 集成向量数据库
class VectorMemory:
    """基于向量相似度的记忆系统"""

    def __init__(self, embedding_model: str = "text-embedding-3-small"):
        self._embeddings: Dict[str, np.ndarray] = {}
        self._experiences: Dict[str, Experience] = {}

        # 使用本地嵌入模型 (避免API依赖)
        try:
            from sentence_transformers import SentenceTransformer
            self._encoder = SentenceTransformer('all-MiniLM-L6-v2')
        except ImportError:
            self._encoder = None

    def store(self, experience: Experience) -> None:
        """存储经验"""
        if self._encoder is None:
            return

        # 生成嵌入向量
        text = f"{experience.vuln_type} {experience.pattern} {experience.context}"
        embedding = self._encoder.encode(text)

        self._embeddings[experience.id] = embedding
        self._experiences[experience.id] = experience

    def recall(self, query: str, top_k: int = 5) -> List[Experience]:
        """召回相似经验"""
        if self._encoder is None or not self._embeddings:
            return []

        query_embedding = self._encoder.encode(query)

        # 计算相似度
        similarities = []
        for exp_id, exp_embedding in self._embeddings.items():
            sim = np.dot(query_embedding, exp_embedding)
            similarities.append((exp_id, sim))

        # 返回 top-k
        similarities.sort(key=lambda x: x[1], reverse=True)
        return [self._experiences[exp_id] for exp_id, _ in similarities[:top_k]]
```

### 6.2 错误处理规范化

```python
# 定义明确的异常层次
class LuoDllHackAIError(Exception):
    """AI模块基础异常"""
    pass

class AgentInitializationError(LuoDllHackAIError):
    """Agent 初始化失败"""
    pass

class TaskExecutionError(LuoDllHackAIError):
    """任务执行失败"""
    pass

class LLMBackendError(LuoDllHackAIError):
    """LLM 后端错误"""
    pass

# 在关键位置使用明确的异常
class BaseAgent:
    def __init__(self, ...):
        try:
            self._init_llm_backend()
        except Exception as e:
            raise AgentInitializationError(
                f"Failed to initialize {self.agent_id}: {e}"
            ) from e

    def process_task(self, task: TaskAssignment) -> AgentResult:
        try:
            handler = self._task_handlers.get(task.task_type)
            if handler is None:
                raise TaskExecutionError(f"Unknown task type: {task.task_type}")
            return handler(task)
        except LuoDllHackAIError:
            raise  # 已知异常直接抛出
        except Exception as e:
            raise TaskExecutionError(f"Task {task.task_id} failed: {e}") from e
```

### 6.3 类型提示完善

```python
# 创建类型定义文件 luodllhack/ai/types.py
from typing import Protocol, TypeVar, Generic, Dict, Any, Optional
from dataclasses import dataclass

T = TypeVar('T')

class LLMBackendProtocol(Protocol):
    """LLM 后端协议"""

    def generate(
        self,
        prompt: str,
        temperature: float = 0.7,
        max_tokens: int = 4096
    ) -> str:
        ...

    def is_available(self) -> bool:
        ...

class ToolRegistryProtocol(Protocol):
    """工具注册表协议"""

    def call_tool(self, tool_name: str, params: Dict[str, Any]) -> 'ToolResult':
        ...

    def get_tool_dict(self) -> Dict[str, 'ToolDefinition']:
        ...

# 在 BaseAgent 中使用
class BaseAgent:
    def __init__(
        self,
        agent_id: str,
        llm_pool: LLMBackendProtocol,  # 明确类型
        tool_registry: ToolRegistryProtocol,  # 明确类型
        shared_state: SharedState,
        message_bus: MessageBus,
        config: Optional[Dict[str, Any]] = None
    ) -> None:
        ...
```

---

## 实施时间表

```
Week 1-2:   Phase 1.1 - agent.py 拆分 (ToolRegistry, ReAct)
Week 3:     Phase 1.2 - 条件导入清理
Week 4-5:   Phase 2 - 统一通信模型
Week 6-7:   Phase 3 - SharedState 优化
Week 8-9:   Phase 4 - 工作流重构
Week 10:    Phase 5 - Agent 整合
Week 11+:   Phase 6 - 持续优化
```

---

## 风险与缓解

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| 拆分导致回归 | 功能异常 | 完善单元测试，保持接口兼容 |
| 通信模型变更 | 性能下降 | 基准测试，灰度切换 |
| 工作流变更 | 分析效果下降 | A/B 测试，保留回退路径 |
| Agent 合并 | 职责不清 | 明确文档，代码审查 |

---

## 成功标准

1. **代码质量**: agent.py 行数 < 500，所有模块 < 800 行
2. **数据一致性**: 报告统计数据 100% 一致
3. **并发性能**: SharedState 锁争用下降 50%
4. **测试覆盖**: 核心模块覆盖率 > 80%
5. **类型检查**: mypy 通过率 > 95%
