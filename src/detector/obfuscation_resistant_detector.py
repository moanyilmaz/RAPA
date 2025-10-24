"""
Anti-Obfuscation Detection Module
Implements multi-level obfuscation resistance strategies for SSAR analysis
"""
import re
import hashlib
from typing import List, Dict, Any, Optional, Set
from pathlib import Path
import javalang
from javalang.tree import MethodDeclaration, MethodInvocation, MemberReference, VariableDeclarator

from src.utils.logger import log


class ObfuscationPatternDetector:
    """Detect common obfuscation patterns"""
    
    def __init__(self):
        # Common obfuscated variable name patterns
        self.obfuscated_patterns = {
            'short_names': r'^[a-z]{1,3}$',  # a, b, c, aa, bb, etc.
            'number_suffix': r'^[a-z]+\d+$',  # a1, b2, c3, etc.
            'hash_like': r'^[a-f0-9]{8,}$',  # hash-like names
            'proguard_style': r'^[a-z]\d+$',  # a1, b2, c3 style
        }
        
        # Sensor-related method signatures (even when obfuscated)
        self.sensor_method_signatures = {
            'onSensorChanged': {
                'param_count': 1,
                'param_types': ['SensorEvent'],
                'return_type': 'void'
            },
            'onAccuracyChanged': {
                'param_count': 2,
                'param_types': ['Sensor', 'int'],
                'return_type': 'void'
            }
        }
        
        # Sensor-related class patterns
        self.sensor_class_patterns = [
            r'.*Sensor.*',
            r'.*Manager.*',
            r'.*Listener.*',
            r'.*Event.*'
        ]
    
    def detect_obfuscation_level(self, content: str) -> Dict[str, Any]:
        """Detect the level of code obfuscation"""
        obfuscation_indicators = {
            'variable_obfuscation': 0,
            'method_obfuscation': 0,
            'string_encryption': 0,
            'control_flow_obfuscation': 0
        }
        
        # Analyze variable names
        variable_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        variables = re.findall(variable_pattern, content)
        
        for var in variables:
            if self._is_obfuscated_name(var):
                obfuscation_indicators['variable_obfuscation'] += 1
        
        # Analyze method names
        method_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\([^)]*\)\s*\{'
        methods = re.findall(method_pattern, content)
        
        for method in methods:
            if self._is_obfuscated_name(method):
                obfuscation_indicators['method_obfuscation'] += 1
        
        # Detect string encryption
        string_encryption_patterns = [
            r'String\s*\.\s*valueOf\s*\([^)]+\)',
            r'new\s+String\s*\([^)]+\)',
            r'decode\s*\([^)]+\)',
            r'decrypt\s*\([^)]+\)'
        ]
        
        for pattern in string_encryption_patterns:
            if re.search(pattern, content):
                obfuscation_indicators['string_encryption'] += 1
        
        # Detect control flow obfuscation
        control_flow_patterns = [
            r'goto\s+\w+',
            r'label\s+\w+:',
            r'switch\s*\([^)]+\)\s*\{[^}]*default:',
        ]
        
        for pattern in control_flow_patterns:
            if re.search(pattern, content):
                obfuscation_indicators['control_flow_obfuscation'] += 1
        
        return obfuscation_indicators
    
    def _is_obfuscated_name(self, name: str) -> bool:
        """Check if a name appears to be obfuscated"""
        for pattern in self.obfuscated_patterns.values():
            if re.match(pattern, name):
                return True
        return False


class SemanticSensorDetector:
    """Detect sensor logic based on semantic patterns rather than exact names"""
    
    def __init__(self):
        self.sensor_semantic_patterns = {
            # Method call patterns that indicate sensor registration
            'registration_patterns': [
                r'\.registerListener\s*\(',
                r'\.addListener\s*\(',
                r'\.setListener\s*\(',
                r'\.subscribe\s*\(',
            ],
            
            # Parameter patterns that indicate sensor types
            'sensor_type_patterns': [
                r'TYPE_ACCELEROMETER',
                r'TYPE_GRAVITY',
                r'TYPE_LINEAR_ACCELERATION',
                r'TYPE_GYROSCOPE',
                r'TYPE_ROTATION_VECTOR',
            ],
            
            # Event handling patterns
            'event_patterns': [
                r'\.getValues\s*\(',
                r'\.getData\s*\(',
                r'\.getEvent\s*\(',
                r'\.onEvent\s*\(',
            ],
            
            # More specific threshold comparison patterns
            'threshold_patterns': [
                r'[><=!]=?\s*\d+\.?\d*',
                r'Math\.abs\s*\(',
                r'Math\.sqrt\s*\(',
                r'Math\.pow\s*\(',
            ],
            
            # Additional sensor-specific patterns
            'sensor_specific_patterns': [
                r'onSensorChanged\s*\(',
                r'onAccuracyChanged\s*\(',
                r'SensorEvent\s*\w*',
                r'SensorManager',
                r'getDefaultSensor\s*\(',
                r'getSensorList\s*\(',
            ]
        }
    
    def detect_sensor_logic_semantic(self, content: str) -> Dict[str, Any]:
        """Detect sensor logic using semantic patterns"""
        semantic_features = {
            'has_registration': False,
            'has_event_handling': False,
            'has_threshold_comparison': False,
            'has_math_operations': False,
            'has_sensor_specific_patterns': False,
            'sensor_types': set(),
            'threshold_values': [],
            'registration_calls': [],
            'sensor_specific_count': 0
        }
        
        # Check for registration patterns
        for pattern in self.sensor_semantic_patterns['registration_patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                semantic_features['has_registration'] = True
                semantic_features['registration_calls'].append(pattern)
        
        # Check for sensor type references
        for pattern in self.sensor_semantic_patterns['sensor_type_patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                semantic_features['sensor_types'].add(pattern)
        
        # Check for event handling
        for pattern in self.sensor_semantic_patterns['event_patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                semantic_features['has_event_handling'] = True
        
        # Check for sensor-specific patterns (higher weight)
        for pattern in self.sensor_semantic_patterns['sensor_specific_patterns']:
            if re.search(pattern, content, re.IGNORECASE):
                semantic_features['has_sensor_specific_patterns'] = True
                semantic_features['sensor_specific_count'] += 1
        
        # Check for threshold comparisons (but with context)
        threshold_matches = re.findall(r'([><=!]=?)\s*(\d+\.?\d*)', content)
        if threshold_matches:
            # Only count if there's also sensor-related context
            if (semantic_features['has_registration'] or 
                semantic_features['has_event_handling'] or 
                semantic_features['has_sensor_specific_patterns']):
                semantic_features['has_threshold_comparison'] = True
                semantic_features['threshold_values'].extend(threshold_matches)
        
        # Check for math operations (but with context)
        math_patterns = [r'Math\.abs\s*\(', r'Math\.sqrt\s*\(', r'Math\.pow\s*\(']
        for pattern in math_patterns:
            if re.search(pattern, content):
                # Only count if there's also sensor-related context
                if (semantic_features['has_registration'] or 
                    semantic_features['has_event_handling'] or 
                    semantic_features['has_sensor_specific_patterns']):
                    semantic_features['has_math_operations'] = True
                    break
        
        return semantic_features


class ControlFlowAnalyzer:
    """Analyze control flow to detect sensor logic even with obfuscation"""
    
    def __init__(self):
        self.control_flow_patterns = {
            # Conditional blocks that might contain sensor logic
            'conditional_patterns': [
                r'if\s*\([^)]*\)\s*\{[^}]*\}',
                r'while\s*\([^)]*\)\s*\{[^}]*\}',
                r'for\s*\([^)]*\)\s*\{[^}]*\}',
            ],
            
            # Method call chains that might indicate sensor processing
            'method_chains': [
                r'\w+\.\w+\.\w+\([^)]*\)',
                r'\w+\([^)]*\)\.\w+\([^)]*\)',
            ]
        }
    
    def analyze_control_flow(self, content: str) -> Dict[str, Any]:
        """Analyze control flow for sensor-related patterns"""
        flow_analysis = {
            'complex_conditionals': 0,
            'method_chains': 0,
            'nested_blocks': 0,
            'potential_sensor_blocks': []
        }
        
        # Count complex conditional statements
        for pattern in self.control_flow_patterns['conditional_patterns']:
            matches = re.findall(pattern, content, re.DOTALL)
            flow_analysis['complex_conditionals'] += len(matches)
        
        # Count method call chains
        for pattern in self.control_flow_patterns['method_chains']:
            matches = re.findall(pattern, content)
            flow_analysis['method_chains'] += len(matches)
        
        # Analyze nested blocks
        nested_pattern = r'\{\s*\{[^}]*\}\s*\}'
        flow_analysis['nested_blocks'] = len(re.findall(nested_pattern, content, re.DOTALL))
        
        return flow_analysis


class ObfuscationResistantDetector:
    """Main anti-obfuscation detector that combines multiple strategies"""
    
    def __init__(self):
        self.pattern_detector = ObfuscationPatternDetector()
        self.semantic_detector = SemanticSensorDetector()
        self.flow_analyzer = ControlFlowAnalyzer()
        
        # Load configuration
        try:
            from config.settings import (
                ENABLE_ANTI_OBFUSCATION, ENABLE_STRING_DECODING, 
                ENABLE_SEMANTIC_DETECTION, ENABLE_CONTROL_FLOW_ANALYSIS,
                OBFUSCATION_CONFIDENCE_THRESHOLD
            )
            self.enable_anti_obfuscation = ENABLE_ANTI_OBFUSCATION
            self.enable_string_decoding = ENABLE_STRING_DECODING
            self.enable_semantic_detection = ENABLE_SEMANTIC_DETECTION
            self.enable_control_flow_analysis = ENABLE_CONTROL_FLOW_ANALYSIS
            self.confidence_threshold = OBFUSCATION_CONFIDENCE_THRESHOLD
        except ImportError:
            # Use default values if config is not available
            self.enable_anti_obfuscation = True
            self.enable_string_decoding = True
            self.enable_semantic_detection = True
            self.enable_control_flow_analysis = True
            self.confidence_threshold = 0.6
    
    def detect_sensor_logic_robust(self, file_path: str, content: str) -> Dict[str, Any]:
        """Robust sensor logic detection with anti-obfuscation capabilities"""
        
        # Check if anti-obfuscation is enabled
        if not self.enable_anti_obfuscation:
            return {
                'file_path': file_path,
                'content': content,
                'obfuscation_level': {},
                'semantic_features': {},
                'flow_analysis': {},
                'confidence_score': 0.0,
                'is_likely_sensor_logic': False
            }
        
        # Step 1: Detect obfuscation level
        obfuscation_level = self.pattern_detector.detect_obfuscation_level(content)
        
        # Step 2: Semantic analysis (if enabled)
        if self.enable_semantic_detection:
            semantic_features = self.semantic_detector.detect_sensor_logic_semantic(content)
        else:
            semantic_features = {
                'has_registration': False,
                'has_event_handling': False,
                'has_threshold_comparison': False,
                'has_math_operations': False,
                'sensor_types': set(),
                'threshold_values': [],
                'registration_calls': []
            }
        
        # Step 3: Control flow analysis (if enabled)
        if self.enable_control_flow_analysis:
            flow_analysis = self.flow_analyzer.analyze_control_flow(content)
        else:
            flow_analysis = {
                'complex_conditionals': 0,
                'method_chains': 0,
                'nested_blocks': 0,
                'potential_sensor_blocks': []
            }
        
        # Step 4: Combine results
        confidence_score = self._calculate_confidence(obfuscation_level, semantic_features, flow_analysis)
        is_likely_sensor_logic = self._is_likely_sensor_logic(semantic_features, flow_analysis)
        
        result = {
            'file_path': file_path,
            'content': content,  # Include original content for compatibility
            'obfuscation_level': obfuscation_level,
            'semantic_features': semantic_features,
            'flow_analysis': flow_analysis,
            'confidence_score': confidence_score,
            'is_likely_sensor_logic': is_likely_sensor_logic
        }
        
        return result
    
    def _calculate_confidence(self, obfuscation_level: Dict, semantic_features: Dict, flow_analysis: Dict) -> float:
        """Calculate confidence score based on multiple factors"""
        confidence = 0.0
        
        # Higher weight for sensor-specific patterns
        if semantic_features['has_sensor_specific_patterns']:
            confidence += 0.4
            # Bonus for multiple sensor-specific patterns
            confidence += min(0.2, semantic_features['sensor_specific_count'] * 0.1)
        
        # Base confidence from semantic features (lower weight for generic patterns)
        if semantic_features['has_registration']:
            confidence += 0.2
        if semantic_features['has_event_handling']:
            confidence += 0.15
        if semantic_features['has_threshold_comparison']:
            confidence += 0.1  # Reduced weight
        if semantic_features['has_math_operations']:
            confidence += 0.05  # Reduced weight
        if semantic_features['sensor_types']:
            confidence += 0.15
        
        # Adjust for obfuscation level
        obfuscation_penalty = sum(obfuscation_level.values()) * 0.05
        confidence = max(0.0, confidence - obfuscation_penalty)
        
        # Bonus for complex control flow (reduced weight)
        if flow_analysis['complex_conditionals'] > 0:
            confidence += 0.05  # Reduced from 0.1
        
        return min(1.0, confidence)
    
    def _is_likely_sensor_logic(self, semantic_features: Dict, flow_analysis: Dict) -> bool:
        """Determine if the code is likely to contain sensor logic"""
        
        # Must have sensor-specific patterns OR (registration AND event handling)
        has_sensor_logic = (
            semantic_features['has_sensor_specific_patterns'] or
            (semantic_features['has_registration'] and semantic_features['has_event_handling'])
        )
        
        # Must have some form of data processing (but more restrictive)
        has_data_processing = (
            semantic_features['has_threshold_comparison'] or
            semantic_features['has_math_operations']
        )
        
        # Additional requirement: must have sensor types or sensor-specific patterns
        has_sensor_context = (
            semantic_features['sensor_types'] or
            semantic_features['has_sensor_specific_patterns']
        )
        
        return has_sensor_logic and has_data_processing and has_sensor_context 