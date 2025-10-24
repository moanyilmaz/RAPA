"""
Algorithm 1: Sensor Logic Detection
Implements file-level filtering and method-level analysis for shake-to-show-ad detection
"""
import os
import re
from typing import Dict, List, Tuple, Optional, Set
from pathlib import Path
import javalang
from javalang.tree import MethodDeclaration, MethodInvocation, MemberReference

from src.utils.logger import log


class SensorFeatureMatrix:
    """AST feature recognition matrix"""
    
    # Detection pattern regular expressions
    PATTERNS = {
        "event_listener": r"SensorManager\.registerListener",
        "callback_method": r"onSensorChanged",
        "sensor_type": r"Sensor\.TYPE"
    }

    def __init__(self):
        self.features = {
            "has_sensor_registration": False,
            "has_sensor_callback": False,  
            "has_sensor_type": False,
            "sensor_types": set(),
            "callback_methods": [],
            "registration_calls": []
        }
    
    def reset(self):
        """Reset feature matrix"""
        self.features = {
            "has_sensor_registration": False,
            "has_sensor_callback": False,
            "has_sensor_type": False,
            "sensor_types": set(),
            "callback_methods": [],
            "registration_calls": []
        }


class SensorLogicDetector:
    """Sensor logic detector"""
    
    def __init__(self):
        self.feature_matrix = SensorFeatureMatrix()
        
        # Keyword sets
        self.sensor_keywords = {
            "SensorEvent", "onSensorChanged", "SensorManager",
            "registerListener", "unregisterListener", "Sensor.TYPE"
        }
        
        # Shake-related keywords
        self.shake_keywords = {
            "shake", "Shake", "SHAKE",
            "acceleration", "accelerometer", "ACCELEROMETER",
            "vibrate", "motion", "gesture"
        }
    
    def file_level_filter(self, directory: str) -> List[Tuple[str, str]]:
        """
        File-level filtering: Find Java files containing sensor-related code
        
        Args:
            directory: Search directory
            
        Returns:
            List[Tuple[str, str]]: List of (file_path, file_content) tuples
        """
        log.info(f"Starting file-level filtering: {directory}")
        
        candidate_files = []
        java_files_count = 0
        
        for root, _, files in os.walk(directory):
            for file in files:
                if not file.endswith(".java"):
                    continue
                    
                java_files_count += 1
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
                    # Check if contains sensor-related keywords
                    if self._contains_sensor_logic(content):
                        candidate_files.append((file_path, content))
                        log.debug(f"Candidate file: {file_path}")
                        
                except Exception as e:
                    log.warning(f"Failed to read file {file_path}: {e}")
        
        log.info(f"File-level filtering completed: scanned {java_files_count} Java files, "
                f"found {len(candidate_files)} candidate files")
        
        return candidate_files
    
    def _contains_sensor_logic(self, content: str) -> bool:
        """
        Check if file content contains sensor logic
        
        Args:
            content: File content
            
        Returns:
            bool: Whether contains sensor logic
        """
        # Basic sensor keyword check
        has_sensor_keywords = any(keyword in content for keyword in self.sensor_keywords)
        
        # Shake-related check
        has_shake_keywords = any(keyword in content for keyword in self.shake_keywords)
        
        # Sensor method call chain check
        has_sensor_chain = (
            "SensorEvent" in content and
            ("onSensorChanged" in content or "onAccuracyChanged" in content) and
            ("registerListener" in content or "SensorManager" in content)
        )
        
        return has_sensor_keywords and (has_shake_keywords or has_sensor_chain)
    
    def method_level_analysis(self, file_path: str, content: str) -> Optional[Dict]:
        """
        Method-level analysis and feature matrix construction
        
        Args:
            file_path: File path
            content: File content
            
        Returns:
            Optional[Dict]: Analysis result, None if not qualified
        """
        log.debug(f"Starting method-level analysis: {file_path}")
        
        try:
            # Pre-process content to handle common parsing issues
            processed_content = self._preprocess_java_content(content)
            
            # Parse AST
            tree = javalang.parse.parse(processed_content)
            self.feature_matrix.reset()
            
            # Analyze AST nodes
            self._analyze_ast_nodes(tree)
            
            # Check if meets sensor logic features
            if self._is_valid_sensor_logic():
                result = {
                    "file_path": file_path,
                    "features": self.feature_matrix.features.copy(),
                    "ast_tree": tree,
                    "content": content
                }
                
                log.success(f"Found valid sensor logic: {file_path}")
                return result
            else:
                log.debug(f"Does not meet sensor logic features: {file_path}")
                return None
                
        except javalang.parser.JavaSyntaxError as e:
            log.warning(f"Java syntax error in {file_path}: {e}")
            log.debug(f"Syntax error details: line {getattr(e, 'at', 'unknown')}")
            # Log problematic lines for debugging
            lines = content.split('\n')
            if hasattr(e, 'at') and e.at and hasattr(e.at, 'line'):
                line_num = e.at.line
                if 0 <= line_num < len(lines):
                    log.debug(f"Problematic line {line_num}: {lines[line_num]}")
            return None
        except Exception as e:
            log.warning(f"AST parsing failed {file_path}: {e}")
            log.debug(f"Error type: {type(e).__name__}")
            log.debug(f"File content preview (first 200 chars): {content[:200]}...")
            # Log file size and basic info
            log.debug(f"File size: {len(content)} characters, {len(content.split())} words")
            return None
    
    def _analyze_ast_nodes(self, tree) -> None:
        """Analyze AST nodes and build feature matrix"""
        
        # Check MethodInvocation nodes (event listener registration)
        for path, node in tree.filter(MethodInvocation):
            if node.member == "registerListener":
                self.feature_matrix.features["has_sensor_registration"] = True
                self.feature_matrix.features["registration_calls"].append({
                    "method": node.member,
                    "qualifier": getattr(node, 'qualifier', None)
                })
        
        # Check MethodDeclaration nodes (data callback methods)
        for path, node in tree.filter(MethodDeclaration):
            if node.name == "onSensorChanged":
                self.feature_matrix.features["has_sensor_callback"] = True
                self.feature_matrix.features["callback_methods"].append({
                    "name": node.name,
                    "parameters": [param.name for param in node.parameters] if node.parameters else []
                })
        
        # Check MemberReference nodes (type selection)
        for path, node in tree.filter(MemberReference):
            if hasattr(node, 'member') and "TYPE" in node.member:
                self.feature_matrix.features["has_sensor_type"] = True
                self.feature_matrix.features["sensor_types"].add(node.member)
    
    def _preprocess_java_content(self, content: str) -> str:
        # Remove problematic comments that might cause parsing issues
        import re
        
        # Remove single-line comments that might contain problematic characters
        content = re.sub(r'//.*$', '', content, flags=re.MULTILINE)
        
        # Remove multi-line comments
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        
        # Remove problematic annotations that might cause parsing issues
        content = re.sub(r'@\w+\([^)]*\)', '', content)
        
        # Remove problematic lambda expressions that might cause parsing issues
        # This is a simplified approach - in practice, you might need more sophisticated handling
        content = re.sub(r'->\s*\{[^}]*\}', '-> {}', content)
        
        return content
    
    def _is_valid_sensor_logic(self) -> bool:
        """Check if it is valid sensor logic"""
        features = self.feature_matrix.features
        
        # Basic requirement: must have sensor callback method
        if not features["has_sensor_callback"]:
            return False
        
        # Must meet at least one of the following conditions:
        # 1. Has sensor registration calls
        # 2. Has sensor type references
        return (
            features["has_sensor_registration"] or 
            features["has_sensor_type"]
        )
    
    def analyze_directory(self, directory: str) -> List[Dict]:
        """
        Analyze all files in specified directory
        
        Args:
            directory: Directory path
            
        Returns:
            List[Dict]: List of analysis results
        """
        log.info(f"Starting sensor logic detection: {directory}")
        
        # File-level filtering
        candidate_files = self.file_level_filter(directory)
        
        if not candidate_files:
            log.warning("No candidate files found")
            return []
        
        # Method-level analysis
        valid_results = []
        parse_failures = 0
        
        for file_path, content in candidate_files:
            result = self.method_level_analysis(file_path, content)
            if result:
                valid_results.append(result)
            else:
                parse_failures += 1
        
        log.info(f"Sensor logic detection completed: found {len(valid_results)} valid files")
        if parse_failures > 0:
            log.info(f"Parse failures: {parse_failures} files (due to syntax errors or obfuscation)")
        
        return valid_results



