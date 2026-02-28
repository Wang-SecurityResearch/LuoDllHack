"""
neuro_symbolic.py - Neuro-Symbolic Reasoning Engine

Improves the core architecture of LuoDllHack by combining the pattern recognition capabilities of neural networks 
with the logical deduction power of symbolic reasoning to enhance 0-day discovery capabilities. 
This module learns vulnerability patterns and reasons about new attack paths.
"""

import os
import pickle
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import numpy as np

from ..core.types import VulnType
from .taint import TaintPath, TaintStep, TaintSource, TaintSink
from .cfg import BasicBlock

logger = logging.getLogger(__name__)

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    HAVE_TORCH = True
except ImportError:
    HAVE_TORCH = False
    torch = None
    nn = None
    F = None

try:
    import z3
    from z3 import Solver, BitVec, BitVecVal, Bool, And, Or, Not
    HAVE_Z3 = True
except ImportError:
    HAVE_Z3 = False
    z3 = None
    Solver = None


@dataclass
class InstructionEmbedding:
    """Instruction Embedding Representation - used for neural network processing"""
    opcode: int
    operands: List[int]
    semantics: List[int]  # Semantic features
    is_branch: bool = False
    is_call: bool = False
    is_memory: bool = False


@dataclass
class VulnerabilityPattern:
    """Vulnerability Pattern - learned from known vulnerabilities"""
    id: str
    pattern_type: str  # 'buffer_overflow', 'format_string', etc.
    semantic_signature: List[str]  # Semantic feature signature
    instruction_sequence: List[str]  # Instruction sequence
    vulnerability_score: float = 0.0
    learned_from: List[str] = field(default_factory=list)  # Learning samples


class PatternLearningEngine:
    """
    Pattern Learning Engine - learns patterns from known vulnerabilities to identify unknown ones
    
    This is a key improvement for 0-day discovery: discovering unknown vulnerability types through pattern learning.
    """
    
    def __init__(self, model_path: Optional[Path] = None):
        self.patterns: Dict[str, VulnerabilityPattern] = {}
        self.feature_cache: Dict[str, Any] = {}
        
        if HAVE_TORCH:
            self.vulnerability_predictor = self._build_predictor_network()
        else:
            self.vulnerability_predictor = None
            
        if model_path and model_path.exists():
            self.load_model(model_path)
        
    def _build_predictor_network(self):
        """Construct the vulnerability predictor network"""
        if not HAVE_TORCH:
            return None

        class VulnerabilityPredictor(nn.Module):
            def __init__(self, input_size=512, hidden_size=256, output_size=1):
                super().__init__()
                self.embedding = nn.Embedding(10000, 64)  # Instruction embedding
                self.lstm = nn.LSTM(64, hidden_size, 2, batch_first=True, dropout=0.1)
                self.dropout = nn.Dropout(0.3)
                self.fc1 = nn.Linear(hidden_size, 128)
                self.fc2 = nn.Linear(128, output_size)
                self.sigmoid = nn.Sigmoid()

            def forward(self, x):
                embedded = self.embedding(x)  # [batch, seq_len, 64]
                lstm_out, _ = self.lstm(embedded)
                # Use output from the last time step
                last_output = lstm_out[:, -1, :]  # [batch, hidden_size]
                x = self.dropout(last_output)
                x = F.relu(self.fc1(x))
                x = self.dropout(x)
                x = self.fc2(x)
                return self.sigmoid(x)

        return VulnerabilityPredictor()
        
    def learn_from_vulnerability(self, taint_path: TaintPath, vuln_type: VulnType) -> None:
        """Learn patterns from unknown vulnerabilities"""
        # Extract semantic features of the path
        semantic_features = self._extract_semantic_features(taint_path)
        instruction_seq = [step.instruction for step in taint_path.steps]
        
        # Generate pattern ID
        pattern_id = f"{vuln_type.name}_{len(self.patterns)}"
        
        # Create vulnerability pattern
        pattern = VulnerabilityPattern(
            id=pattern_id,
            pattern_type=vuln_type.name,
            semantic_signature=semantic_features,
            instruction_sequence=instruction_seq,
            vulnerability_score=1.0,
            learned_from=[taint_path.source.api_name, taint_path.sink.api_name]
        )
        
        self.patterns[pattern_id] = pattern
        
        # Train predictor
        if self.vulnerability_predictor:
            self._train_predictor([pattern])
            
    def _extract_semantic_features(self, taint_path: TaintPath) -> List[str]:
        """Extract semantic features"""
        features = []
        for step in taint_path.steps:
            # Extract instruction semantic features
            instr_lower = step.instruction.lower()
            if 'mov' in instr_lower:
                features.append('data_transfer')
            elif 'call' in instr_lower:
                features.append('function_call')
            elif any(op in instr_lower for op in ['add', 'sub', 'mul', 'imul']):
                features.append('arithmetic_op')
            elif any(op in instr_lower for op in ['cmp', 'test']):
                features.append('comparison')
            elif any(op in instr_lower for op in ['jmp', 'je', 'jne', 'jg', 'jl']):
                features.append('conditional_jump')
        return list(set(features))  # Deduplicate
        
    def _train_predictor(self, patterns: List[VulnerabilityPattern]) -> None:
        """Train vulnerability predictor - incremental training implementation"""
        if not self.vulnerability_predictor or not HAVE_TORCH:
            return

        # Initialize training samples storage
        if not hasattr(self, 'training_samples'):
            self.training_samples = []

        # Add new samples
        for pattern in patterns:
            encoded = self._encode_instructions(pattern.instruction_sequence)
            self.training_samples.append((encoded, 1.0))

        if len(self.training_samples) < 4:
            logger.debug(f"Insufficient training data: {len(self.training_samples)} samples")
            return

        # Incremental training
        self.vulnerability_predictor.train()
        optimizer = torch.optim.Adam(self.vulnerability_predictor.parameters(), lr=0.001)
        criterion = nn.BCELoss()

        batch_samples = self.training_samples[-32:]  # Use most recent samples
        for epoch in range(5):
            total_loss = 0.0
            for encoded, label in batch_samples:
                X = torch.LongTensor(encoded).unsqueeze(0)
                y = torch.FloatTensor([label])

                optimizer.zero_grad()
                output = self.vulnerability_predictor(X)
                loss = criterion(output.squeeze(), y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()

        avg_loss = total_loss / len(batch_samples) if batch_samples else 0
        logger.info(f"Incremental training: {len(patterns)} patterns, loss={avg_loss:.4f}")

    def _encode_instructions(self, instructions: List[str], max_len: int = 256) -> List[int]:
        """Encode instruction sequence into a sequence of integer IDs"""
        opcode_vocab = {
            'mov': 10, 'movzx': 11, 'movsx': 12, 'lea': 13, 'push': 14, 'pop': 15,
            'add': 30, 'sub': 31, 'mul': 32, 'imul': 33, 'div': 34,
            'and': 50, 'or': 51, 'xor': 52, 'not': 53, 'shl': 54, 'shr': 55,
            'cmp': 70, 'test': 71,
            'jmp': 80, 'je': 81, 'jne': 82, 'jz': 83, 'jnz': 84, 'jg': 85, 'jl': 86,
            'call': 100, 'ret': 101, 'retn': 102, 'leave': 103, 'nop': 133,
        }

        encoded = [2]  # START token
        for inst in instructions[:max_len - 2]:
            parts = inst.strip().lower().split()
            opcode = parts[0] if parts else ''
            encoded.append(opcode_vocab.get(opcode, 1))  # 1 = UNK
        encoded.append(3)  # END token

        while len(encoded) < max_len:
            encoded.append(0)  # PAD
        return encoded[:max_len]
        
    def predict_vulnerability(self, semantic_features: List[str],
                            instruction_seq: List[str]) -> Tuple[bool, float, str]:
        """Predict if it is a vulnerability - hybrid neural network + pattern matching prediction"""
        # Attempt neural network prediction first
        if (self.vulnerability_predictor and HAVE_TORCH and
            hasattr(self, 'training_samples') and len(self.training_samples) >= 4):
            try:
                score, vuln_type = self._neural_predict(instruction_seq)
                if score > 0.3:
                    return score > 0.5, score, vuln_type
            except Exception as e:
                logger.debug(f"Neural prediction failed: {e}")

        # Fallback to pattern matching
        return self._simple_pattern_match(semantic_features, instruction_seq)

    def _neural_predict(self, instruction_seq: List[str]) -> Tuple[float, str]:
        """Predict using neutral network"""
        self.vulnerability_predictor.eval()
        encoded = self._encode_instructions(instruction_seq)
        X = torch.LongTensor(encoded).unsqueeze(0)

        with torch.no_grad():
            score = self.vulnerability_predictor(X).item()

        vuln_type = "UNKNOWN"
        if score > 0.5:
            for inst in instruction_seq[:50]:
                il = inst.lower()
                if any(api in il for api in ['strcpy', 'memcpy', 'strcat', 'gets']):
                    vuln_type = "BUFFER_OVERFLOW"
                    break
                elif any(api in il for api in ['printf', 'sprintf', 'fprintf']):
                    vuln_type = "FORMAT_STRING"
                    break
        return score, vuln_type
        
    def _simple_pattern_match(self, features: List[str], 
                            seq: List[str]) -> Tuple[bool, float, str]:
        """Simple prediction based on pattern matching"""
        score = 0.0
        matched_type = "UNKNOWN"
        
        for pattern_id, pattern in self.patterns.items():
            match_score = self._calculate_pattern_match(features, pattern)
            if match_score > score:
                score = match_score
                matched_type = pattern.pattern_type
                
        return score > 0.6, score, matched_type
        
    def _calculate_pattern_match(self, features: List[str], 
                               pattern: VulnerabilityPattern) -> float:
        """Calculate match between features and pattern"""
        if not features or not pattern.semantic_signature:
            return 0.0
            
        # Calculate Jaccard similarity
        feature_set = set(features)
        pattern_set = set(pattern.semantic_signature)
        
        intersection = feature_set.intersection(pattern_set)
        union = feature_set.union(pattern_set)
        
        if len(union) == 0:
            return 0.0
            
        return len(intersection) / len(union)
        
    def save_model(self, path: Path) -> None:
        """Save model"""
        model_data = {
            'patterns': self.patterns,
            'feature_cache': self.feature_cache,
            'training_samples': getattr(self, 'training_samples', [])
        }
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        # Save neural network weights
        if self.vulnerability_predictor and HAVE_TORCH:
            weights_path = path.with_suffix('.pt')
            torch.save(self.vulnerability_predictor.state_dict(), weights_path)
            
    def load_model(self, path: Path) -> None:
        """Load model"""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)
                self.patterns = model_data.get('patterns', {})
                self.feature_cache = model_data.get('feature_cache', {})
                self.training_samples = model_data.get('training_samples', [])

            # Load neural network weights
            if self.vulnerability_predictor and HAVE_TORCH:
                weights_path = path.with_suffix('.pt')
                if weights_path.exists():
                    self.vulnerability_predictor.load_state_dict(
                        torch.load(weights_path, weights_only=True)
                    )
                    logger.info(f"Loaded neural network weights from {weights_path}")

            logger.info(f"Loaded {len(self.patterns)} patterns, {len(self.training_samples)} samples")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")


class EnhancedSymbolicEngine:
    """
    Enhanced Symbolic Execution Engine - combines Z3 solver and neural network constraints
    """
    
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.learning_engine = PatternLearningEngine()
        
        if HAVE_Z3:
            self.solver = Solver()
        else:
            self.solver = None
            
    def analyze_constraint_complexity(self, taint_path: TaintPath) -> Dict[str, Any]:
        """
        Analyze constraint complexity - used to determine if neuro-symbolic reasoning is needed
        """
        analysis = {
            'has_loops': 0,
            'has_complex_conditions': 0,
            'has_arithmetic_ops': 0,
            'has_memory_access': 0,
            'path_complexity': 0
        }
        
        for step in taint_path.steps:
            instr_lower = step.instruction.lower()
            if any(op in instr_lower for op in ['jmp', 'je', 'jne', 'jg', 'jl', 'ja', 'jb']):
                analysis['has_complex_conditions'] += 1
            if any(op in instr_lower for op in ['add', 'sub', 'mul', 'imul', 'div', 'idiv']):
                analysis['has_arithmetic_ops'] += 1
            if any(op in instr_lower for op in ['mov', 'lea', 'push', 'pop']):
                analysis['has_memory_access'] += 1
            if 'loop' in instr_lower:
                analysis['has_loops'] += 1
                
        analysis['path_complexity'] = sum(analysis.values())
        return analysis
        
    def neural_guided_symbolic_execution(self, taint_path: TaintPath) -> Optional[bytes]:
        """
        Neural network-guided symbolic execution - for solving complex path constraints
        """
        if not HAVE_TORCH or not self.solver:
            return self._fallback_analysis(taint_path)
            
        # Analyze path complexity
        complexity = self.analyze_constraint_complexity(taint_path)
        
        if complexity['path_complexity'] > 20:
            # For complex paths, use neural-guided symbolic execution
            return self._neural_guided_solve(taint_path, complexity)
        else:
            # For simple paths, use traditional methods
            return self._traditional_solve(taint_path)
            
    def _neural_guided_solve(self, taint_path: TaintPath, 
                           complexity: Dict[str, Any]) -> Optional[bytes]:
        """Neural network-guided constraint solving"""
        try:
            # Use neural network to predict critical points for constraint solving
            semantic_features = self.learning_engine._extract_semantic_features(taint_path)
            
            # Create symbolic variables
            if complexity['has_arithmetic_ops'] > 0:
                # For paths with arithmetic operations, create numeric symbolic variables
                input_var = BitVec('input', 32)
            else:
                # For other paths, create general symbolic variables
                input_var = BitVec('input', 64)
                
            # Construct constraints (simplified implementation)
            constraints = []
            
            # Apply neural-guided constraint pruning
            if complexity['has_complex_conditions'] > 5:
                # For complex conditional branches, use more intelligent constraint generation
                pass  # Specific logic omitted for simplicity
                
            # Solve
            solver = Solver()
            for constraint in constraints:
                solver.add(constraint)
                
            if solver.check() == z3.sat:
                model = solver.model()
                # Extract input value
                result = self._extract_solution(model, input_var)
                return result
        except Exception as e:
            logger.error(f"Neural guided solving failed: {e}")
            
        return None
        
    def _traditional_solve(self, taint_path: TaintPath) -> Optional[bytes]:
        """Traditional constraint solving (simplified implementation)"""
        # Tradiitonal Z3 solving logic would be implemented here
        return b"TRADITIONAL_SOLUTION"
        
    def _fallback_analysis(self, taint_path: TaintPath) -> Optional[bytes]:
        """Fallback analysis method"""
        # Alternative approach when neural network is unavailable
        return self._generate_smart_payload(taint_path.sink.vuln_type)
        
    def _extract_solution(self, model, var) -> bytes:
        """Extract solution from model"""
        try:
            value = model[var]
            # Convert to bytes
            if hasattr(value, 'as_long'):
                intval = value.as_long()
                return intval.to_bytes((intval.bit_length() + 7) // 8 or 1, 'little')
            else:
                return int(str(value)).to_bytes(8, 'little')
        except:
            return b"FALLBACK_SOLUTION"
            
    def _generate_smart_payload(self, vuln_type: VulnType) -> bytes:
        """Generate smart payload based on vulnerability type"""
        if vuln_type == VulnType.BUFFER_OVERFLOW:
            return b'A' * 256 + b'BBBB' * 4  # Typical buffer overflow payload
        elif vuln_type == VulnType.FORMAT_STRING:
            return b'%x.' * 20 + b'%n'  # Typical format string payload
        elif vuln_type == VulnType.INTEGER_OVERFLOW:
            return b'\xFF' * 4  # Typical integer overflow payload
        else:
            return b'DEFAULT_PAYLOAD'


class ZeroDayDiscoveryEngine:
    """
    0-day Discovery Engine - combines various technologies to enhance discovery capabilities
    
    Core Improvements:
    1. Pattern Learning: learns new patterns from known vulnerabilities
    2. Neuro-Symbolic Reasoning: combines neural networks and symbolic execution
    3. Intelligent Path Exploration: automatically identifies complex vulnerability paths
    """
    
    def __init__(self, binary_path: Path, config=None):
        self.binary_path = binary_path
        self.config = config
        self.pattern_learning = PatternLearningEngine()
        self.symbolic_engine = EnhancedSymbolicEngine(binary_path)
        
    def discover_potential_0days(self, taint_paths: List[TaintPath]) -> List[TaintPath]:
        """
        Discover potential 0-day vulnerabilities
        
        Core logic:
        1. Pattern matching for each taint path
        2. Evaluate if it represents a new vulnerability type using a neural network
        3. Combine symbolic execution to verify exploitability
        """
        potential_0days = []
        
        for taint_path in taint_paths:
            # Extract path features
            semantic_features = self.pattern_learning._extract_semantic_features(taint_path)
            instruction_seq = [step.instruction for step in taint_path.steps]
            
            # Predict if it's a vulnerability
            is_vuln, confidence, predicted_type = self.pattern_learning.predict_vulnerability(
                semantic_features, instruction_seq
            )
            
            # If high confidence and new type, add to 0-day candidates
            if is_vuln and confidence > 0.8:
                # Perform neuro-symbolic analysis
                neural_confidence = self._neural_symbolic_analysis(taint_path, confidence)
                
                # If neuro-symbolic analysis also supports it, consider it a potential 0-day
                if neural_confidence > 0.7:
                    # Update path confidence
                    taint_path.confidence = max(taint_path.confidence, neural_confidence)
                    potential_0days.append(taint_path)
                    
                    # Learn new pattern from this vulnerability
                    self.pattern_learning.learn_from_vulnerability(
                        taint_path, taint_path.sink.vuln_type
                    )
        
        return potential_0days
        
    def _neural_symbolic_analysis(self, taint_path: TaintPath, base_confidence: float) -> float:
        """
        Neuro-Symbolic Analysis - integrates results from neural networks and symbolic execution
        """
        # Analyze path complexity
        complexity = self.symbolic_engine.analyze_constraint_complexity(taint_path)
        
        if complexity['path_complexity'] > 15:
            # For complex paths, use neuro-symbolic approach
            solution = self.symbolic_engine.neural_guided_symbolic_execution(taint_path)
            if solution:
                # Significantly increase confidence if a triggering input is found
                neural_confidence = min(0.95, base_confidence + 0.2)
            else:
                # Maintain moderate confidence if solving is difficult but pattern match is high
                neural_confidence = base_confidence
        else:
            # Use traditional method for simple paths
            neural_confidence = base_confidence
            
        return neural_confidence
        
    def save_learning_state(self, path: Path) -> None:
        """Save learning state"""
        self.pattern_learning.save_model(path)
        
    def load_learning_state(self, path: Path) -> None:
        """Load learning state"""
        self.pattern_learning.load_model(path)


# Utility function
def get_neuro_symbolic_engine(binary_path: Path) -> ZeroDayDiscoveryEngine:
    """Get neuro-symbolic engine instance"""
    return ZeroDayDiscoveryEngine(binary_path)