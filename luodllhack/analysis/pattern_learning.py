"""
pattern_learning.py - Vulnerability Pattern Learning System

Implements machine learning-based vulnerability pattern discovery, which is the core of true 0-day discovery capabilities.
The system is capable of learning patterns from known vulnerabilities and identifying new, unknown vulnerability types.
"""

import pickle
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass, field
import logging
import numpy as np
from collections import defaultdict, Counter

from ..core.types import VulnType
from .taint import TaintPath, TaintStep
from .cfg import BasicBlock
from ..analysis.neuro_symbolic import VulnerabilityPattern

logger = logging.getLogger(__name__)

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from torch.utils.data import Dataset, DataLoader
    HAVE_TORCH = True
except ImportError:
    HAVE_TORCH = False
    torch = None
    nn = None
    F = None

try:
    from sklearn.cluster import DBSCAN, KMeans
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.decomposition import PCA
    HAVE_SKLEARN = True
except ImportError:
    HAVE_SKLEARN = False


@dataclass
class CodePattern:
    """Code Pattern - Extracted from assembly code"""
    id: str
    asm_sequence: List[str]
    semantic_features: List[str]
    control_flow_features: Dict[str, Any]
    data_flow_features: Dict[str, Any]
    vulnerability_score: float = 0.0
    cluster_id: Optional[int] = None
    similarity_to_known: float = 0.0


class AssemblyEmbedder:
    """Assembly Instruction Embedder - Converts assembly instructions to numerical vectors"""
    
    def __init__(self):
        # Common assembly instruction vocabulary
        self.opcode_vocab = {
            'mov': 1, 'lea': 2, 'add': 3, 'sub': 4, 'mul': 5, 'div': 6,
            'imul': 7, 'idiv': 8, 'inc': 9, 'dec': 10, 'neg': 11, 'not': 12,
            'and': 13, 'or': 14, 'xor': 15, 'shl': 16, 'shr': 17, 'sal': 18, 'sar': 19,
            'rol': 20, 'ror': 21, 'clc': 22, 'stc': 23, 'cld': 24, 'std': 25,
            'jmp': 26, 'je': 27, 'jne': 28, 'jg': 29, 'jl': 30, 'jge': 31, 'jle': 32,
            'ja': 33, 'jb': 34, 'jae': 35, 'jbe': 36, 'call': 37, 'ret': 38, 'push': 39, 'pop': 40,
            'cmp': 41, 'test': 42, 'nop': 43, 'int': 44, 'syscall': 45, 'sysenter': 46,
            'leave': 47, 'enter': 48, 'loop': 49, 'loope': 50, 'loopne': 51,
            # Add more instructions...
        }
        
        # Operand type mapping
        self.operand_types = {
            'reg': 100, 'mem': 101, 'imm': 102, 'label': 103
        }
        
        # Semantic operation categories
        self.semantic_classes = {
            'data_transfer': 0, 'arithmetic': 1, 'logic': 2, 'control_flow': 3,
            'memory_access': 4, 'stack_operation': 5, 'system_call': 6
        }
        
    def embed_instruction(self, instruction: str) -> Dict[str, Any]:
        """Embeds a single assembly instruction as a feature vector"""
        parts = instruction.strip().split()
        if not parts:
            return {'opcode': 0, 'operands': [], 'semantic_class': 0}
            
        opcode = parts[0].lower()
        operands_str = ' '.join(parts[1:]) if len(parts) > 1 else ''
        
        # Get opcode ID
        opcode_id = self.opcode_vocab.get(opcode, 0)
        
        # Analyze semantic category
        semantic_class = self._classify_semantic(opcode)
        
        # Analyze operands
        operand_features = self._analyze_operands(operands_str)
        
        return {
            'opcode': opcode_id,
            'operands': operand_features,
            'semantic_class': semantic_class,
            'raw': instruction
        }
        
    def _classify_semantic(self, opcode: str) -> int:
        """Classifies the semantic type of an instruction"""
        if opcode in ['mov', 'lea', 'push', 'pop']:
            return self.semantic_classes['data_transfer']
        elif opcode in ['add', 'sub', 'mul', 'div', 'inc', 'dec', 'neg']:
            return self.semantic_classes['arithmetic']
        elif opcode in ['and', 'or', 'xor', 'not', 'shl', 'shr']:
            return self.semantic_classes['logic']
        elif opcode in ['jmp', 'je', 'jne', 'call', 'ret']:
            return self.semantic_classes['control_flow']
        elif opcode in ['cmp', 'test']:
            return self.semantic_classes['memory_access']  # Comparisons usually involve memory access
        else:
            return self.semantic_classes['data_transfer']  # Default
            
    def _analyze_operands(self, operands: str) -> List[int]:
        """Analyzes operand features"""
        features = []
        if not operands:
            return features
            
        # Simplified operand analysis
        if 'r' in operands or 'e' in operands:  # Register
            features.append(self.operand_types['reg'])
        if '[' in operands and ']' in operands:  # Memory access
            features.append(self.operand_types['mem'])
        if any(c.isdigit() for c in operands):  # Immediate
            features.append(self.operand_types['imm'])
            
        return features if features else [0]
        
    def embed_sequence(self, instruction_seq: List[str]) -> List[Dict[str, Any]]:
        """Embeds an instruction sequence as a sequence of feature vectors"""
        return [self.embed_instruction(inst) for inst in instruction_seq]


class PatternExtractor:
    """Pattern Extractor - Extracts features from taint paths and control flow graphs"""
    
    def __init__(self):
        self.embedder = AssemblyEmbedder()
        
    def extract_from_taint_path(self, taint_path: TaintPath) -> CodePattern:
        """Extracts code pattern from a taint path"""
        # Extract instruction sequence
        asm_seq = [step.instruction for step in taint_path.steps]
        
        # Extract semantic features
        semantic_features = self._extract_semantic_features(asm_seq)
        
        # Extract control flow features
        control_flow_features = self._extract_control_flow_features(taint_path)
        
        # Extract data flow features
        data_flow_features = self._extract_data_flow_features(taint_path)
        
        # Calculate vulnerability score (based on path features)
        vuln_score = self._calculate_vulnerability_score(taint_path)
        
        # Generate pattern ID
        pattern_id = f"path_{hash(str(asm_seq)) % 1000000}"
        
        return CodePattern(
            id=pattern_id,
            asm_sequence=asm_seq,
            semantic_features=semantic_features,
            control_flow_features=control_flow_features,
            data_flow_features=data_flow_features,
            vulnerability_score=vuln_score
        )
        
    def _extract_semantic_features(self, asm_seq: List[str]) -> List[str]:
        """Extracts semantic features"""
        features = set()
        
        for inst in asm_seq:
            inst_lower = inst.lower()
            
            # Data transfer features
            if any(op in inst_lower for op in ['mov', 'lea', 'push', 'pop']):
                features.add('data_transfer')
                
            # Arithmetic features
            if any(op in inst_lower for op in ['add', 'sub', 'mul', 'imul', 'div', 'idiv']):
                features.add('arithmetic')
                
            # Logic features
            if any(op in inst_lower for op in ['and', 'or', 'xor', 'not', 'shl', 'shr']):
                features.add('logic')
                
            # Control flow features
            if any(op in inst_lower for op in ['jmp', 'je', 'jne', 'jg', 'jl', 'call', 'ret']):
                features.add('control_flow')
                
            # Comparison features
            if any(op in inst_lower for op in ['cmp', 'test']):
                features.add('comparison')
                
            # Memory access features
            if '[' in inst and ']' in inst:
                features.add('memory_access')
                
            # System call features
            if any(syscall in inst_lower for syscall in ['syscall', 'int', 'sysenter']):
                features.add('system_call')
                
        return list(features)
        
    def _extract_control_flow_features(self, taint_path: TaintPath) -> Dict[str, Any]:
        """Extracts control flow features"""
        features = {
            'branch_count': 0,
            'loop_count': 0,
            'function_call_count': 0,
            'indirect_call_count': 0,
            'call_depth': 1,
            'complexity_score': 0.0
        }
        
        for step in taint_path.steps:
            inst_lower = step.instruction.lower()
            
            if any(op in inst_lower for op in ['jmp', 'je', 'jne', 'jg', 'jl', 'ja', 'jb']):
                features['branch_count'] += 1
            if 'loop' in inst_lower:
                features['loop_count'] += 1
            if 'call' in inst_lower:
                if 'rax' in inst_lower or 'rbx' in inst_lower or '[' in inst_lower:
                    features['indirect_call_count'] += 1
                else:
                    features['function_call_count'] += 1
                    
        # Calculate complexity score
        features['complexity_score'] = (
            features['branch_count'] * 0.3 +
            features['loop_count'] * 0.4 +
            features['function_call_count'] * 0.2 +
            features['indirect_call_count'] * 0.1
        )
        
        return features
        
    def _extract_data_flow_features(self, taint_path: TaintPath) -> Dict[str, Any]:
        """Extracts data flow features"""
        features = {
            'taint_propagation_steps': len(taint_path.steps),
            'pointer_operations': 0,
            'arithmetic_operations': 0,
            'memory_operations': 0,
            'input_dependent_operations': 0
        }
        
        for step in taint_path.steps:
            inst_lower = step.instruction.lower()
            
            if any(op in inst_lower for op in ['lea', 'mov'] if any(reg in inst_lower for reg in ['rax', 'rbx', 'rcx', 'rdx'])):
                features['pointer_operations'] += 1
            if any(op in inst_lower for op in ['add', 'sub', 'mul', 'imul', 'div', 'idiv']):
                features['arithmetic_operations'] += 1
            if '[' in inst_lower:  # Memory operation
                features['memory_operations'] += 1
            if 'input' in step.effect or 'taint' in step.effect:
                features['input_dependent_operations'] += 1
                
        return features
        
    def _calculate_vulnerability_score(self, taint_path: TaintPath) -> float:
        """Calculates vulnerability score"""
        score = 0.0
        
        # Score based on taint path characteristics
        if taint_path.sink.vuln_type in [VulnType.BUFFER_OVERFLOW, VulnType.HEAP_OVERFLOW]:
            score += 0.3
        elif taint_path.sink.vuln_type == VulnType.FORMAT_STRING:
            score += 0.25
        elif taint_path.sink.vuln_type in [VulnType.USE_AFTER_FREE, VulnType.DOUBLE_FREE]:
            score += 0.35
            
        # Score based on path length
        path_length = len(taint_path.steps)
        if path_length > 10:
            score += min(0.2, path_length * 0.01)
            
        # Score based on control flow complexity
        control_complexity = sum(1 for step in taint_path.steps 
                               if any(op in step.instruction.lower() 
                                    for op in ['jmp', 'je', 'jne', 'call', 'loop']))
        score += min(0.15, control_complexity * 0.02)
        
        return min(1.0, score)


class ZeroShotVulnerabilityDetector:
    """
    Zero-Shot Vulnerability Detector - Capable of detecting unseen vulnerability types.

    Core Capabilities:
    1. Unsupervised learning of vulnerability patterns
    2. Clustering of similar vulnerability patterns
    3. Detection of abnormal patterns (potential new vulnerabilities)
    4. Neural network anomaly detection
    """

    def __init__(self):
        self.pattern_extractor = PatternExtractor()
        self.patterns: List[CodePattern] = []
        self.clusters: Dict[int, List[CodePattern]] = {}
        self.known_vulnerability_signatures: Dict[str, Set[str]] = {
            'buffer_overflow': {'mov', 'cmp', 'call', 'ret', 'memory_access'},
            'format_string': {'call', 'lea', 'push', 'system_call'},
            'integer_overflow': {'add', 'mul', 'imul', 'arithmetic', 'compare'},
            'use_after_free': {'call', 'mov', 'memory_access', 'pointer_operations'}
        }

        # Feature matrix for clustering
        self.feature_matrix = None
        self.cluster_model = None

        # Neural network anomaly detector
        self.anomaly_detector = None
        if HAVE_TORCH:
            self.anomaly_detector = self._build_anomaly_detector()

    def _build_anomaly_detector(self):
        """Builds an autoencoder-based anomaly detector"""
        if not HAVE_TORCH:
            return None

        class AnomalyAutoencoder(nn.Module):
            """Autoencoder for anomaly detection - larger reconstruction error indicates anomaly"""
            def __init__(self, input_dim=16, latent_dim=8):
                super().__init__()
                self.encoder = nn.Sequential(
                    nn.Linear(input_dim, 12),
                    nn.ReLU(),
                    nn.Linear(12, latent_dim),
                    nn.ReLU()
                )
                self.decoder = nn.Sequential(
                    nn.Linear(latent_dim, 12),
                    nn.ReLU(),
                    nn.Linear(12, input_dim),
                    nn.Sigmoid()
                )

            def forward(self, x):
                latent = self.encoder(x)
                reconstructed = self.decoder(latent)
                return reconstructed

            def get_anomaly_score(self, x):
                """Calculates reconstruction error as anomaly score"""
                self.eval()
                with torch.no_grad():
                    reconstructed = self.forward(x)
                    mse = torch.mean((x - reconstructed) ** 2, dim=1)
                return mse

        return AnomalyAutoencoder()
        
    def learn_from_known_vulnerabilities(self, taint_paths: List[TaintPath]) -> None:
        """Learns patterns from known vulnerabilities"""
        logger.info(f"Learning from {len(taint_paths)} known vulnerability paths...")
        
        for path in taint_paths:
            try:
                pattern = self.pattern_extractor.extract_from_taint_path(path)
                self.patterns.append(pattern)
                
                # Record features related to known vulnerability types
                vuln_type = path.sink.vuln_type.name.lower()
                if vuln_type not in self.known_vulnerability_signatures:
                    self.known_vulnerability_signatures[vuln_type] = set()
                self.known_vulnerability_signatures[vuln_type].update(pattern.semantic_features)
                
            except Exception as e:
                logger.warning(f"Failed to extract pattern from path: {e}")
                
        # Perform clustering analysis
        self._perform_clustering()
        
    def _perform_clustering(self) -> None:
        """Performs clustering analysis"""
        if not self.patterns or not HAVE_SKLEARN:
            return

        try:
            # Prepare feature matrix
            feature_vectors = self._create_feature_matrix()
            self.feature_matrix = feature_vectors

            if len(feature_vectors) < 2:
                return

            # Use DBSCAN for clustering (discovers clusters of arbitrary shape and identifies outliers)
            self.cluster_model = DBSCAN(eps=0.5, min_samples=2)
            cluster_labels = self.cluster_model.fit_predict(feature_vectors)

            # Organize clustering results
            self.clusters = defaultdict(list)
            for i, label in enumerate(cluster_labels):
                self.clusters[label].append(self.patterns[i])
                self.patterns[i].cluster_id = label

            # Record anomalies (label=-1 indicates outliers identified by DBSCAN)
            anomaly_count = sum(1 for label in cluster_labels if label == -1)
            logger.info(f"Clustering completed: {len(self.clusters)} clusters, {anomaly_count} anomalies")

            # Train neural network anomaly detector
            if self.anomaly_detector and HAVE_TORCH and len(feature_vectors) >= 4:
                self._train_anomaly_detector(feature_vectors)

        except Exception as e:
            logger.error(f"Clustering failed: {e}")

    def _train_anomaly_detector(self, feature_vectors: List[List[float]]) -> None:
        """Trains the anomaly detection autoencoder"""
        if not self.anomaly_detector or not HAVE_TORCH:
            return

        try:
            # Prepare training data - normalization
            X = np.array(feature_vectors, dtype=np.float32)
            self.feature_mean = X.mean(axis=0)
            self.feature_std = X.std(axis=0) + 1e-8
            X_norm = (X - self.feature_mean) / self.feature_std

            X_tensor = torch.FloatTensor(X_norm)

            # Train autoencoder
            self.anomaly_detector.train()
            optimizer = torch.optim.Adam(self.anomaly_detector.parameters(), lr=0.01)
            criterion = nn.MSELoss()

            for epoch in range(100):
                optimizer.zero_grad()
                reconstructed = self.anomaly_detector(X_tensor)
                loss = criterion(reconstructed, X_tensor)
                loss.backward()
                optimizer.step()

            # Calculate threshold for training data reconstruction error
            self.anomaly_detector.eval()
            with torch.no_grad():
                train_scores = self.anomaly_detector.get_anomaly_score(X_tensor)
                self.anomaly_threshold = train_scores.mean().item() + 2 * train_scores.std().item()

            logger.info(f"Anomaly detector trained, threshold={self.anomaly_threshold:.4f}")

        except Exception as e:
            logger.error(f"Failed to train anomaly detector: {e}")
            
    def _create_feature_matrix(self) -> List[List[float]]:
        """Creates feature matrix for clustering"""
        feature_list = []
        
        for pattern in self.patterns:
            # Convert various features to numerical vectors
            features = [
                pattern.vulnerability_score,
                len(pattern.asm_sequence),
                len(pattern.semantic_features),
                pattern.control_flow_features.get('complexity_score', 0.0),
                pattern.control_flow_features.get('branch_count', 0),
                pattern.control_flow_features.get('loop_count', 0),
                pattern.data_flow_features.get('taint_propagation_steps', 0),
                pattern.data_flow_features.get('arithmetic_operations', 0),
                pattern.data_flow_features.get('memory_operations', 0),
            ]
            
            # Add one-hot encoding for semantic features
            semantic_vocab = ['data_transfer', 'arithmetic', 'logic', 'control_flow', 
                            'memory_access', 'system_call', 'comparison']
            for semantic in semantic_vocab:
                features.append(1.0 if semantic in pattern.semantic_features else 0.0)
                
            feature_list.append(features)
            
        return feature_list
        
    def detect_novel_vulnerabilities(self, new_taint_paths: List[TaintPath]) -> List[Tuple[TaintPath, float, str]]:
        """
        Detects novel vulnerabilities - discovers unknown vulnerability patterns using unsupervised learning.

        Multi-strategy combined detection:
        1. Novelty detection based on similarity
        2. Neural network anomaly detection
        3. Cluster outlier detection

        Returns:
            List of (taint_path, novelty_score, reason) tuples
        """
        if not new_taint_paths:
            return []

        results = []

        for path in new_taint_paths:
            try:
                # Extract pattern of the new path
                new_pattern = self.pattern_extractor.extract_from_taint_path(path)

                # Strategy 1: Calculate similarity to known patterns
                similarity_score = self._calculate_similarity_to_known(new_pattern)
                similarity_novelty = 1.0 - similarity_score

                # Strategy 2: Neural network anomaly detection
                neural_anomaly_score = self._neural_anomaly_detection(new_pattern)

                # Strategy 3: Check if it falls into cluster anomaly regions
                cluster_anomaly_score = self._cluster_anomaly_detection(new_pattern)

                # Combine results from the three strategies
                novelty_score = self._combine_detection_scores(
                    similarity_novelty, neural_anomaly_score, cluster_anomaly_score
                )

                # If novelty is high, it might be a new vulnerability type
                if novelty_score > 0.6:
                    reason = self._analyze_novelty_reason(
                        new_pattern, similarity_novelty, neural_anomaly_score, cluster_anomaly_score
                    )
                    results.append((path, novelty_score, reason))

            except Exception as e:
                logger.debug(f"Error analyzing path for novelty: {e}")

        return results

    def _neural_anomaly_detection(self, pattern: CodePattern) -> float:
        """Neural network-based anomaly detection"""
        if not self.anomaly_detector or not HAVE_TORCH:
            return 0.5  # Return neutral score when detection is unavailable

        if not hasattr(self, 'feature_mean') or not hasattr(self, 'anomaly_threshold'):
            return 0.5

        try:
            # Convert pattern to feature vector
            features = self._pattern_to_feature_vector(pattern)
            X = np.array([features], dtype=np.float32)

            # Normalization
            X_norm = (X - self.feature_mean) / self.feature_std
            X_tensor = torch.FloatTensor(X_norm)

            # Calculate anomaly score
            anomaly_score = self.anomaly_detector.get_anomaly_score(X_tensor).item()

            # Convert to 0-1 range novelty score
            if anomaly_score > self.anomaly_threshold:
                return min(1.0, anomaly_score / (self.anomaly_threshold * 2))
            return anomaly_score / self.anomaly_threshold * 0.5

        except Exception as e:
            logger.debug(f"Neural anomaly detection failed: {e}")
            return 0.5

    def _cluster_anomaly_detection(self, pattern: CodePattern) -> float:
        """Cluster-based anomaly detection"""
        if not self.clusters or not self.feature_matrix:
            return 0.5

        try:
            # Convert pattern to feature vector
            features = self._pattern_to_feature_vector(pattern)

            # Calculate minimum distance to all cluster centers
            min_distance = float('inf')

            for cluster_id, cluster_patterns in self.clusters.items():
                if cluster_id == -1:  # Skip outlier cluster
                    continue

                # Calculate cluster center
                cluster_features = []
                for cp in cluster_patterns:
                    cf = self._pattern_to_feature_vector(cp)
                    cluster_features.append(cf)

                if not cluster_features:
                    continue

                center = np.mean(cluster_features, axis=0)
                distance = np.linalg.norm(np.array(features) - center)
                min_distance = min(min_distance, distance)

            # Convert distance to anomaly score
            if min_distance == float('inf'):
                return 0.5

            # Use average distance of training data as baseline
            avg_distance = np.mean([np.std(self.feature_matrix, axis=0).sum()])
            if avg_distance > 0:
                return min(1.0, min_distance / (avg_distance * 3))
            return 0.5

        except Exception as e:
            logger.debug(f"Cluster anomaly detection failed: {e}")
            return 0.5

    def _pattern_to_feature_vector(self, pattern: CodePattern) -> List[float]:
        """Converts pattern to feature vector"""
        features = [
            pattern.vulnerability_score,
            len(pattern.asm_sequence),
            len(pattern.semantic_features),
            pattern.control_flow_features.get('complexity_score', 0.0),
            pattern.control_flow_features.get('branch_count', 0),
            pattern.control_flow_features.get('loop_count', 0),
            pattern.data_flow_features.get('taint_propagation_steps', 0),
            pattern.data_flow_features.get('arithmetic_operations', 0),
            pattern.data_flow_features.get('memory_operations', 0),
        ]

        semantic_vocab = ['data_transfer', 'arithmetic', 'logic', 'control_flow',
                        'memory_access', 'system_call', 'comparison']
        for semantic in semantic_vocab:
            features.append(1.0 if semantic in pattern.semantic_features else 0.0)

        return features

    def _combine_detection_scores(self, similarity: float, neural: float, cluster: float) -> float:
        """Combines scores from multiple detection strategies"""
        # Weighted average, higher weight for neural network detection
        weights = {'similarity': 0.3, 'neural': 0.45, 'cluster': 0.25}

        combined = (
            weights['similarity'] * similarity +
            weights['neural'] * neural +
            weights['cluster'] * cluster
        )

        # If any strategy gives high score, boost the total score
        max_score = max(similarity, neural, cluster)
        if max_score > 0.8:
            combined = 0.6 * combined + 0.4 * max_score

        return combined
        
    def _calculate_similarity_to_known(self, new_pattern: CodePattern) -> float:
        """Calculates similarity of a new pattern to known patterns"""
        if not self.patterns:
            return 0.0
            
        similarities = []
        
        for known_pattern in self.patterns:
            # Calculate semantic feature similarity
            known_semantic = set(known_pattern.semantic_features)
            new_semantic = set(new_pattern.semantic_features)
            
            if known_semantic and new_semantic:
                intersection = known_semantic.intersection(new_semantic)
                union = known_semantic.union(new_semantic)
                semantic_sim = len(intersection) / len(union) if union else 0
            else:
                semantic_sim = 0.0
                
            # Calculate control flow similarity
            known_cf = known_pattern.control_flow_features
            new_cf = new_pattern.control_flow_features
            
            cf_sim = self._compare_control_flow(known_cf, new_cf)
            
            # Combined similarity
            combined_sim = 0.7 * semantic_sim + 0.3 * cf_sim
            similarities.append(combined_sim)
            
        # Return maximum similarity (most similar known pattern)
        return max(similarities) if similarities else 0.0
        
    def _compare_control_flow(self, cf1: Dict[str, Any], cf2: Dict[str, Any]) -> float:
        """Compares control flow features"""
        # Simplified control flow similarity calculation
        features = ['branch_count', 'loop_count', 'function_call_count', 'complexity_score']
        
        total_sim = 0.0
        count = 0
        
        for feature in features:
            val1 = cf1.get(feature, 0)
            val2 = cf2.get(feature, 0)
            
            if val1 == 0 and val2 == 0:
                sim = 1.0
            elif val1 == 0 or val2 == 0:
                sim = 0.0
            else:
                # Calculate similarity using relative difference
                max_val = max(val1, val2)
                diff = abs(val1 - val2)
                sim = 1.0 - (diff / max_val)
                
            total_sim += sim
            count += 1
            
        return total_sim / count if count > 0 else 0.0
        
    def _analyze_novelty_reason(self, pattern: CodePattern,
                                similarity_score: float = 0.0,
                                neural_score: float = 0.0,
                                cluster_score: float = 0.0) -> str:
        """Analyzes novelty reasons - synthesizes results from multiple detection strategies"""
        reasons = []

        # Analyze based on detection scores
        if neural_score > 0.7:
            reasons.append(f"Neural anomaly detected (score={neural_score:.2f})")
        if cluster_score > 0.7:
            reasons.append(f"Cluster outlier (score={cluster_score:.2f})")
        if similarity_score > 0.7:
            reasons.append(f"Low similarity to known patterns (score={similarity_score:.2f})")

        # Check for unseen semantic features
        known_features = set()
        for sig_features in self.known_vulnerability_signatures.values():
            known_features.update(sig_features)

        novel_features = set(pattern.semantic_features) - known_features
        if novel_features:
            reasons.append(f"Novel features: {list(novel_features)[:3]}")

        # Check control flow complexity
        complexity = pattern.control_flow_features.get('complexity_score', 0)
        if complexity > 0.8:
            reasons.append(f"High control flow complexity ({complexity:.2f})")

        # Check for special instruction sequences
        if len(pattern.asm_sequence) > 50:
            reasons.append(f"Long instruction sequence ({len(pattern.asm_sequence)} insts)")

        # Check data flow features
        mem_ops = pattern.data_flow_features.get('memory_operations', 0)
        arith_ops = pattern.data_flow_features.get('arithmetic_operations', 0)
        if mem_ops > 10 or arith_ops > 10:
            reasons.append(f"Intensive operations (mem={mem_ops}, arith={arith_ops})")

        if not reasons:
            reasons.append("Pattern differs significantly from known types")

        return "; ".join(reasons)
        
    def save_model(self, path: Path) -> None:
        """Saves the learned model"""
        model_data = {
            'patterns': self.patterns,
            'clusters': dict(self.clusters),
            'known_signatures': self.known_vulnerability_signatures,
            'feature_matrix': self.feature_matrix,
            'feature_mean': getattr(self, 'feature_mean', None),
            'feature_std': getattr(self, 'feature_std', None),
            'anomaly_threshold': getattr(self, 'anomaly_threshold', None),
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

        # Save neural network anomaly detector weights
        if self.anomaly_detector and HAVE_TORCH:
            weights_path = path.with_suffix('.anomaly.pt')
            torch.save(self.anomaly_detector.state_dict(), weights_path)

        logger.info(f"Model saved to {path}")
        
    def load_model(self, path: Path) -> None:
        """Loads a learned model"""
        try:
            with open(path, 'rb') as f:
                model_data = pickle.load(f)

            self.patterns = model_data.get('patterns', [])
            self.clusters = defaultdict(list, model_data.get('clusters', {}))
            self.known_vulnerability_signatures = model_data.get('known_signatures', {})
            self.feature_matrix = model_data.get('feature_matrix')

            # Restore normalization parameters
            if model_data.get('feature_mean') is not None:
                self.feature_mean = model_data['feature_mean']
                self.feature_std = model_data['feature_std']
                self.anomaly_threshold = model_data['anomaly_threshold']

            # Load neural network anomaly detector weights
            if self.anomaly_detector and HAVE_TORCH:
                weights_path = path.with_suffix('.anomaly.pt')
                if weights_path.exists():
                    self.anomaly_detector.load_state_dict(
                        torch.load(weights_path, weights_only=True)
                    )
                    logger.info(f"Loaded anomaly detector from {weights_path}")

            logger.info(f"Model loaded from {path}, {len(self.patterns)} patterns")

        except Exception as e:
            logger.error(f"Failed to load model: {e}")


class AdvancedVulnerabilityMiner:
    """
    Advanced Vulnerability Miner - True 0-day discovery engine.
    
    Combines multiple techniques for vulnerability mining:
    1. Pattern learning
    2. Unsupervised anomaly detection
    3. Neuro-symbolic reasoning
    4. Intelligent fuzzing verification
    """
    
    def __init__(self, binary_path: Path, config=None):
        self.binary_path = binary_path
        self.config = config
        
        # Initialize components
        self.pattern_detector = ZeroShotVulnerabilityDetector()
        self.pattern_extractor = PatternExtractor()
        
    def mine_zero_day_vulnerabilities(self, taint_paths: List[TaintPath]) -> List[TaintPath]:
        """
        Mines 0-day vulnerabilities - true discovery of unknown vulnerabilities.

        Args:
            taint_paths: Taint paths obtained from static analysis

        Returns:
            List of identified potential 0-day vulnerability paths
        """
        logger.info(f"Starting zero-day vulnerability mining on {len(taint_paths)} paths...")

        # Separate confirmed vulnerabilities and paths to be analyzed
        # Confirmed paths are used for learning, unconfirmed paths for detection
        confirmed_paths = [p for p in taint_paths if p.confidence >= 0.7]
        unconfirmed_paths = [p for p in taint_paths if p.confidence < 0.7]

        # Phase 1: Learn patterns only from confirmed vulnerabilities (avoids self-comparison)
        has_baseline = len(self.pattern_detector.patterns) > 0 or len(confirmed_paths) > 0

        if confirmed_paths:
            logger.info(f"Learning from {len(confirmed_paths)} confirmed vulnerability paths")
            self.pattern_detector.learn_from_known_vulnerabilities(confirmed_paths)

        # Phase 2: Novelty detection on unconfirmed paths
        zero_day_candidates = []

        if has_baseline and unconfirmed_paths:
            # When baseline patterns are available, use similarity detection for novelty
            novel_findings = self.pattern_detector.detect_novel_vulnerabilities(unconfirmed_paths)

            for path, novelty_score, reason in novel_findings:
                if novelty_score > 0.7:
                    path.confidence = max(path.confidence, novelty_score)
                    path.analysis_notes.append(f"Zero-day candidate: {reason} (novelty={novel_findings:.2f})")
                    zero_day_candidates.append(path)
                    logger.info(f"Zero-day candidate found at 0x{path.sink.addr:x}: {reason}")
        else:
            # When no baseline patterns, use feature-based detection for potential 0-days
            logger.info("No baseline patterns available, using feature-based detection")
            for path in taint_paths:
                try:
                    pattern = self.pattern_extractor.extract_from_taint_path(path)
                    potential_score = self._calculate_zero_day_potential(pattern, path)

                    if potential_score > 0.6:
                        path.confidence = max(path.confidence, potential_score)
                        path.analysis_notes.append(f"Zero-day potential: score={potential_score:.2f}")
                        zero_day_candidates.append(path)
                        logger.info(f"Potential zero-day at 0x{path.sink.addr:x}: score={potential_score:.2f}")
                except Exception as e:
                    logger.debug(f"Error analyzing path for 0day potential: {e}")

        logger.info(f"Found {len(zero_day_candidates)} zero-day vulnerability candidates")

        # Phase 3: In-depth analysis of candidate paths
        refined_candidates = self._refine_candidates(zero_day_candidates)

        return refined_candidates

    def _calculate_zero_day_potential(self, pattern: CodePattern, path: TaintPath) -> float:
        """
        Calculates 0-day potential score (used when no baseline patterns exist).

        Evaluates based on:
        1. Severity of vulnerability type
        2. Data flow complexity
        3. Control flow complexity
        4. Involvement of user input
        """
        score = 0.0

        # 1. Vulnerability Type Severity (30%)
        high_severity_types = ['control_flow_hijack', 'buffer_overflow', 'use_after_free',
                               'double_free', 'format_string', 'command_injection']
        if path.sink and hasattr(path.sink, 'vuln_type'):
            vuln_name = path.sink.vuln_type.name.lower() if hasattr(path.sink.vuln_type, 'name') else str(path.sink.vuln_type).lower()
            if any(t in vuln_name for t in high_severity_types):
                score += 0.30
            else:
                score += 0.15

        # 2. Data Flow Features (25%)
        df_features = pattern.data_flow_features
        if df_features.get('memory_operations', 0) > 2:
            score += 0.15
        if df_features.get('arithmetic_operations', 0) > 1:
            score += 0.10

        # 3. Control Flow Complexity (25%)
        cf_features = pattern.control_flow_features
        complexity = cf_features.get('complexity_score', 0)
        if complexity > 0.5:
            score += 0.25
        elif complexity > 0.3:
            score += 0.15

        # 4. Semantic Features (20%)
        semantic = set(pattern.semantic_features)
        interesting_features = {'memory_access', 'pointer_arithmetic', 'control_flow', 'user_input'}
        matches = semantic.intersection(interesting_features)
        score += 0.05 * len(matches)

        return min(1.0, score)
        
    def _refine_candidates(self, candidates: List[TaintPath]) -> List[TaintPath]:
        """Refines candidate vulnerabilities"""
        refined = []
        
        for path in candidates:
            # Further analyze path characteristics
            pattern = self.pattern_extractor.extract_from_taint_path(path)
            
            # Check if it actually has vulnerability potential
            if self._assess_vulnerability_potential(pattern):
                refined.append(path)
                
        return refined
        
    def _assess_vulnerability_potential(self, pattern: CodePattern) -> bool:
        """Assesses vulnerability potential of a pattern"""
        # Check for vulnerability-related semantic features
        vulnerability_indicators = [
            'memory_access', 'arithmetic', 'control_flow', 'data_transfer'
        ]
        
        has_indicators = any(indicator in pattern.semantic_features 
                           for indicator in vulnerability_indicators)
        
        # Check control flow complexity
        cf_complex = pattern.control_flow_features.get('complexity_score', 0) > 0.3
        
        # Check data flow characteristics
        df_intensive = (pattern.data_flow_features.get('arithmetic_operations', 0) > 2 or
                       pattern.data_flow_features.get('memory_operations', 0) > 3)
        
        # Comprehensive judgment
        return has_indicators and (cf_complex or df_intensive)
        
    def save_learning_state(self, path: Path) -> None:
        """Saves learning state"""
        self.pattern_detector.save_model(path)
        
    def load_learning_state(self, path: Path) -> None:
        """Loads learning state"""
        self.pattern_detector.load_model(path)


# Utility functions
def get_advanced_vulnerability_miner(binary_path: Path, config=None):
    """Retrieves advanced vulnerability miner"""
    return AdvancedVulnerabilityMiner(binary_path, config)