# -*- coding: utf-8 -*-
"""
luodllhack/symbolic/pruning.py - 符号执行路径剪枝策略

提供多种路径剪枝和优化策略:
- 循环检测与边界
- 漏洞导向剪枝
- 路径相似度合并
- 约束优化与缓存
"""

from typing import Dict, List, Set, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from enum import Enum, auto
from collections import defaultdict
import hashlib
import logging

logger = logging.getLogger(__name__)

try:
    import angr
    import claripy
    from angr import SimState
    HAVE_ANGR = True
except ImportError:
    HAVE_ANGR = False
    angr = None
    claripy = None
    SimState = None


class PruningStrategy(Enum):
    """剪枝策略类型"""
    LOOP_BOUND = auto()          # 循环边界限制
    VULN_GUIDED = auto()         # 漏洞点导向
    TAINT_GUIDED = auto()        # 污点传播导向
    COVERAGE_BASED = auto()      # 代码覆盖率导向
    SIMILARITY_MERGE = auto()    # 相似路径合并
    DEPTH_LIMITED = auto()       # 深度限制
    CONSTRAINT_HASH = auto()     # 约束哈希去重


@dataclass
class LoopInfo:
    """循环信息"""
    header_addr: int             # 循环头地址
    back_edge_addr: int          # 回边地址
    body_addrs: Set[int]         # 循环体地址集合
    iteration_count: int = 0     # 当前迭代次数
    max_iterations: int = 3      # 最大迭代次数


@dataclass
class PathScore:
    """路径评分"""
    state_id: int
    score: float
    factors: Dict[str, float] = field(default_factory=dict)

    def __lt__(self, other):
        return self.score < other.score


class LoopDetector:
    """
    循环检测器

    使用 Tarjan 算法检测强连通分量，识别循环结构
    """

    def __init__(self):
        self.loops: Dict[int, LoopInfo] = {}
        self._visit_counts: Dict[int, int] = defaultdict(int)

    def detect_loops_from_cfg(self, cfg) -> List[LoopInfo]:
        """从 CFG 检测循环"""
        if not cfg:
            return []

        loops = []
        # 简化实现：检测回边 (back edge)
        visited = set()
        rec_stack = set()

        def dfs(node, path):
            if node in rec_stack:
                # 发现回边，确定循环
                loop_start = path.index(node)
                loop_body = set(path[loop_start:])
                loop_info = LoopInfo(
                    header_addr=node,
                    back_edge_addr=path[-1] if path else node,
                    body_addrs=loop_body
                )
                loops.append(loop_info)
                self.loops[node] = loop_info
                return

            if node in visited:
                return

            visited.add(node)
            rec_stack.add(node)
            path.append(node)

            # 获取后继节点
            successors = cfg.get(node, [])
            for succ in successors:
                dfs(succ, path.copy())

            rec_stack.remove(node)

        # 从所有入口开始 DFS
        if hasattr(cfg, 'nodes'):
            for node in cfg.nodes:
                if node not in visited:
                    dfs(node, [])
        elif isinstance(cfg, dict):
            for node in cfg.keys():
                if node not in visited:
                    dfs(node, [])

        return loops

    def should_unroll(self, addr: int) -> bool:
        """检查是否应该继续展开循环"""
        if addr not in self.loops:
            return True

        loop = self.loops[addr]
        return loop.iteration_count < loop.max_iterations

    def record_visit(self, addr: int) -> int:
        """记录地址访问，返回访问次数"""
        self._visit_counts[addr] += 1

        # 更新循环迭代计数
        if addr in self.loops:
            self.loops[addr].iteration_count = self._visit_counts[addr]

        return self._visit_counts[addr]

    def get_visit_count(self, addr: int) -> int:
        """获取地址访问次数"""
        return self._visit_counts.get(addr, 0)

    def reset(self):
        """重置状态"""
        self._visit_counts.clear()
        for loop in self.loops.values():
            loop.iteration_count = 0


class VulnGuidedPrioritizer:
    """
    漏洞导向优先级排序

    根据状态与漏洞点的距离和相关性进行优先级排序
    """

    def __init__(self, target_addrs: Set[int] = None,
                 dangerous_apis: Set[str] = None):
        self.target_addrs = target_addrs or set()
        self.dangerous_apis = dangerous_apis or set()
        self.call_graph: Dict[int, Set[int]] = {}

        # 预计算到目标的距离
        self._distance_cache: Dict[int, int] = {}

    def set_targets(self, target_addrs: Set[int]):
        """设置目标地址"""
        self.target_addrs = target_addrs
        self._distance_cache.clear()

    def set_call_graph(self, call_graph: Dict[int, Set[int]]):
        """设置调用图"""
        self.call_graph = call_graph
        self._distance_cache.clear()

    def compute_distance(self, addr: int) -> int:
        """计算到最近目标的距离"""
        if addr in self._distance_cache:
            return self._distance_cache[addr]

        if addr in self.target_addrs:
            self._distance_cache[addr] = 0
            return 0

        # BFS 计算最短距离
        if not self.call_graph:
            return 999999

        visited = {addr}
        queue = [(addr, 0)]

        while queue:
            current, dist = queue.pop(0)

            if current in self.target_addrs:
                self._distance_cache[addr] = dist
                return dist

            # 获取被调用者
            callees = self.call_graph.get(current, set())
            for callee in callees:
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, dist + 1))

        self._distance_cache[addr] = 999999
        return 999999

    def score_state(self, state) -> PathScore:
        """为状态评分"""
        if not HAVE_ANGR or state is None:
            return PathScore(state_id=0, score=0.0)

        factors = {}

        # 因素 1: 到目标的距离
        distance = self.compute_distance(state.addr)
        distance_score = 1.0 / (1.0 + distance * 0.1)
        factors['distance'] = distance_score

        # 因素 2: 路径长度 (较短路径优先)
        history_len = len(state.history.bbl_addrs) if hasattr(state.history, 'bbl_addrs') else 0
        length_score = 1.0 / (1.0 + history_len * 0.01)
        factors['length'] = length_score

        # 因素 3: 约束复杂度 (简单约束优先)
        constraint_count = len(state.solver.constraints) if hasattr(state, 'solver') else 0
        constraint_score = 1.0 / (1.0 + constraint_count * 0.05)
        factors['constraints'] = constraint_score

        # 加权求和
        total_score = (
            distance_score * 0.5 +
            length_score * 0.3 +
            constraint_score * 0.2
        )

        return PathScore(
            state_id=id(state),
            score=total_score,
            factors=factors
        )

    def prioritize_states(self, states: List) -> List:
        """对状态列表排序"""
        if not states:
            return []

        scored = [(self.score_state(s), s) for s in states]
        scored.sort(key=lambda x: x[0].score, reverse=True)

        return [s for _, s in scored]


class ConstraintOptimizer:
    """
    约束优化器

    提供约束简化、缓存和增量求解能力
    """

    def __init__(self, cache_size: int = 1000):
        self.cache_size = cache_size
        self._cache: Dict[str, Any] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def constraint_hash(self, constraints: List) -> str:
        """计算约束哈希"""
        if not constraints:
            return ""

        # 将约束转换为字符串并排序，确保一致性
        constraint_strs = sorted(str(c) for c in constraints)
        combined = "|".join(constraint_strs)

        return hashlib.md5(combined.encode()).hexdigest()

    def simplify(self, constraint) -> Any:
        """简化单个约束"""
        if not HAVE_ANGR or constraint is None:
            return constraint

        try:
            # 使用 claripy 内置简化
            return claripy.simplify(constraint)
        except Exception:
            return constraint

    def simplify_all(self, constraints: List) -> List:
        """简化约束列表"""
        if not constraints:
            return []

        simplified = []
        for c in constraints:
            s = self.simplify(c)
            # 跳过恒真约束
            if hasattr(s, 'is_true') and s.is_true():
                continue
            simplified.append(s)

        return simplified

    def remove_redundant(self, constraints: List) -> List:
        """移除冗余约束"""
        if len(constraints) <= 1:
            return constraints

        # 使用约束哈希去重
        seen = set()
        unique = []

        for c in constraints:
            h = str(c)
            if h not in seen:
                seen.add(h)
                unique.append(c)

        return unique

    def cache_lookup(self, constraints: List) -> Optional[bool]:
        """查找缓存的求解结果"""
        h = self.constraint_hash(constraints)

        if h in self._cache:
            self._cache_hits += 1
            return self._cache[h]

        self._cache_misses += 1
        return None

    def cache_store(self, constraints: List, result: bool):
        """存储求解结果到缓存"""
        h = self.constraint_hash(constraints)

        # LRU 策略
        if len(self._cache) >= self.cache_size:
            # 移除最老的条目
            oldest_key = next(iter(self._cache))
            del self._cache[oldest_key]

        self._cache[h] = result

    def get_cache_stats(self) -> Dict:
        """获取缓存统计"""
        total = self._cache_hits + self._cache_misses
        hit_rate = self._cache_hits / total if total > 0 else 0

        return {
            'hits': self._cache_hits,
            'misses': self._cache_misses,
            'hit_rate': hit_rate,
            'size': len(self._cache)
        }


class PathSimilarityMerger:
    """
    路径相似度合并器

    合并约束相似的路径以减少探索空间
    """

    def __init__(self, similarity_threshold: float = 0.9):
        self.similarity_threshold = similarity_threshold

    def constraint_set(self, state) -> Set[str]:
        """获取状态的约束集合"""
        if not HAVE_ANGR or state is None:
            return set()

        try:
            return {str(c) for c in state.solver.constraints}
        except Exception:
            return set()

    def jaccard_similarity(self, set1: Set, set2: Set) -> float:
        """计算 Jaccard 相似度"""
        if not set1 and not set2:
            return 1.0
        if not set1 or not set2:
            return 0.0

        intersection = len(set1 & set2)
        union = len(set1 | set2)

        return intersection / union if union > 0 else 0.0

    def find_similar(self, state, candidates: List) -> Optional[Any]:
        """找到相似的状态"""
        if not candidates:
            return None

        state_constraints = self.constraint_set(state)

        for candidate in candidates:
            candidate_constraints = self.constraint_set(candidate)
            similarity = self.jaccard_similarity(state_constraints, candidate_constraints)

            if similarity >= self.similarity_threshold:
                return candidate

        return None

    def merge_groups(self, states: List) -> List[List]:
        """将状态分组，相似的放在一起"""
        if not states:
            return []

        groups = []
        assigned = set()

        for i, state in enumerate(states):
            if i in assigned:
                continue

            group = [state]
            assigned.add(i)
            state_constraints = self.constraint_set(state)

            for j, other in enumerate(states[i+1:], start=i+1):
                if j in assigned:
                    continue

                other_constraints = self.constraint_set(other)
                if self.jaccard_similarity(state_constraints, other_constraints) >= self.similarity_threshold:
                    group.append(other)
                    assigned.add(j)

            groups.append(group)

        return groups

    def select_representative(self, group: List) -> Any:
        """从组中选择代表状态 (选择约束最少的)"""
        if not group:
            return None

        return min(group, key=lambda s: len(self.constraint_set(s)))


class SmartPathPruner:
    """
    智能路径剪枝器

    整合多种剪枝策略，提供统一的剪枝接口
    """

    def __init__(self,
                 strategies: List[PruningStrategy] = None,
                 max_loop_iterations: int = 3,
                 max_path_depth: int = 500,
                 max_active_states: int = 100,
                 similarity_threshold: float = 0.9):

        self.strategies = strategies or [
            PruningStrategy.LOOP_BOUND,
            PruningStrategy.VULN_GUIDED,
            PruningStrategy.DEPTH_LIMITED
        ]

        self.max_loop_iterations = max_loop_iterations
        self.max_path_depth = max_path_depth
        self.max_active_states = max_active_states

        # 组件
        self.loop_detector = LoopDetector()
        self.prioritizer = VulnGuidedPrioritizer()
        self.optimizer = ConstraintOptimizer()
        self.merger = PathSimilarityMerger(similarity_threshold)

        # 统计
        self.stats = {
            'states_pruned': 0,
            'loops_bounded': 0,
            'paths_merged': 0,
            'depth_exceeded': 0
        }

    def set_targets(self, target_addrs: Set[int]):
        """设置漏洞目标地址"""
        self.prioritizer.set_targets(target_addrs)

    def set_call_graph(self, call_graph: Dict):
        """设置调用图"""
        self.prioritizer.set_call_graph(call_graph)

    def should_prune(self, state) -> Tuple[bool, str]:
        """
        判断是否应该剪枝

        Returns:
            (should_prune, reason)
        """
        if not HAVE_ANGR or state is None:
            return False, ""

        addr = state.addr

        # 策略 1: 循环边界
        if PruningStrategy.LOOP_BOUND in self.strategies:
            visit_count = self.loop_detector.record_visit(addr)
            if not self.loop_detector.should_unroll(addr):
                self.stats['loops_bounded'] += 1
                return True, f"Loop iteration limit ({self.max_loop_iterations}) reached"

        # 策略 2: 深度限制
        if PruningStrategy.DEPTH_LIMITED in self.strategies:
            if hasattr(state.history, 'bbl_addrs'):
                depth = len(state.history.bbl_addrs)
                if depth > self.max_path_depth:
                    self.stats['depth_exceeded'] += 1
                    return True, f"Path depth ({depth}) exceeds limit ({self.max_path_depth})"

        # 策略 3: 约束哈希去重
        if PruningStrategy.CONSTRAINT_HASH in self.strategies:
            constraints = list(state.solver.constraints) if hasattr(state, 'solver') else []
            h = self.optimizer.constraint_hash(constraints)
            # 这里需要维护一个已见约束集

        return False, ""

    def prune_and_prioritize(self, states: List) -> List:
        """
        剪枝并优先级排序

        Args:
            states: 待处理的状态列表

        Returns:
            处理后的状态列表
        """
        if not states:
            return []

        filtered = []

        # 第一步: 基于规则剪枝
        for state in states:
            should_prune, reason = self.should_prune(state)
            if not should_prune:
                filtered.append(state)
            else:
                self.stats['states_pruned'] += 1
                logger.debug(f"Pruned state at 0x{state.addr:x}: {reason}")

        # 第二步: 相似路径合并
        if PruningStrategy.SIMILARITY_MERGE in self.strategies:
            groups = self.merger.merge_groups(filtered)
            representatives = [self.merger.select_representative(g) for g in groups]
            merged_count = len(filtered) - len(representatives)
            if merged_count > 0:
                self.stats['paths_merged'] += merged_count
                filtered = [r for r in representatives if r is not None]

        # 第三步: 漏洞导向排序
        if PruningStrategy.VULN_GUIDED in self.strategies:
            filtered = self.prioritizer.prioritize_states(filtered)

        # 第四步: 限制活跃状态数量
        if len(filtered) > self.max_active_states:
            self.stats['states_pruned'] += len(filtered) - self.max_active_states
            filtered = filtered[:self.max_active_states]

        return filtered

    def get_stats(self) -> Dict:
        """获取剪枝统计"""
        return {
            **self.stats,
            'cache_stats': self.optimizer.get_cache_stats()
        }

    def reset(self):
        """重置状态"""
        self.loop_detector.reset()
        self.stats = {
            'states_pruned': 0,
            'loops_bounded': 0,
            'paths_merged': 0,
            'depth_exceeded': 0
        }
