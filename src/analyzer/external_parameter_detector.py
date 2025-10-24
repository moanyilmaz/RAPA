"""
External Parameter Detection Module
Implements four types of external parameter passing detection for SSAR behavior analysis
"""
import os
import re
from typing import Dict, List, Optional, Set, Any, Tuple
import javalang
from javalang.tree import (
    ConstructorDeclaration, MethodDeclaration, MethodInvocation, 
    Assignment, VariableDeclarator, MemberReference, ClassDeclaration,
    FieldDeclaration, LocalVariableDeclaration, Literal
)

from src.utils.logger import log


class ExternalParameterDetector:
    """External parameter detector for SSAR threshold analysis"""
    
    def __init__(self):
        # Constructor analysis patterns
        self.config_class_patterns = {
            "Config", "Configuration", "Settings", "Properties", 
            "Preference", "ConfigManager", "ThresholdConfig"
        }
        
        # Setter method patterns
        self.setter_patterns = [
            r"set[A-Z][a-zA-Z]*Threshold",
            r"set[A-Z][a-zA-Z]*Limit", 
            r"set[A-Z][a-zA-Z]*Value",
            r"setThreshold",
            r"setLimit",
            r"setValue"
        ]
        
        # Static configuration file patterns
        self.config_file_patterns = {
            "FileInputStream", "Properties", "Config", "ConfigurationBuilder",
            "PropertyResourceBundle", "ResourceBundle", "ConfigFactory"
        }
        
        # Dynamic data source patterns
        self.dynamic_method_patterns = {
            "fetchThreshold", "getCloudConfig", "getRemoteConfig", 
            "loadFromAPI", "fetchConfig", "getServerConfig",
            "loadConfigFromServer", "fetchFromNetwork", "getNetworkConfig",
            "loadDynamicConfig", "fetchRemoteData"
        }
        
        # Network/API related patterns
        self.network_patterns = {
            "HttpURLConnection", "OkHttpClient", "Retrofit", "Volley",
            "RequestQueue", "JsonObjectRequest", "StringRequest"
        }
    
    def analyze_external_parameters(self, ast_tree, file_path: str = "") -> Dict[str, List[Dict]]:
        """
        Comprehensive analysis of external parameter passing methods
        
        Args:
            ast_tree: Java AST tree
            file_path: Source file path
            
        Returns:
            Dictionary containing all detected external parameter patterns
        """
        log.info(f"Starting external parameter analysis: {file_path}")
        
        results = {
            "constructor_analysis": self._analyze_constructors(ast_tree),
            "setter_method_analysis": self._analyze_setter_methods(ast_tree),
            "static_config_analysis": self._analyze_static_config(ast_tree),
            "dynamic_source_analysis": self._analyze_dynamic_sources(ast_tree)
        }
        
        # Calculate summary statistics
        total_detections = sum(len(patterns) for patterns in results.values())
        log.info(f"External parameter analysis completed: {total_detections} patterns detected")
        
        return results
    
    def _analyze_constructors(self, ast_tree) -> List[Dict]:
        """
        Constructor analysis: Check constructor parameters for configuration classes
        """
        log.debug("Analyzing constructors for configuration parameters")
        constructor_patterns = []
        
        for path, node in ast_tree.filter(ConstructorDeclaration):
            if not node.parameters:
                continue
                
            for param in node.parameters:
                param_type = str(param.type) if hasattr(param.type, 'name') else str(param.type)
                
                # Check if parameter type is a configuration class
                if any(config_pattern in param_type for config_pattern in self.config_class_patterns):
                    constructor_info = {
                        "type": "constructor_config",
                        "constructor_name": getattr(node, 'name', 'unknown'),
                        "parameter_name": param.name,
                        "parameter_type": param_type,
                        "assignments": self._extract_constructor_assignments(node, param.name)
                    }
                    constructor_patterns.append(constructor_info)
                    log.debug(f"Found config constructor parameter: {param.name} ({param_type})")
        
        return constructor_patterns
    
    def _extract_constructor_assignments(self, constructor_node, param_name: str) -> List[Dict]:
        """Extract assignment operations in constructor body related to the parameter"""
        assignments = []
        
        if not constructor_node.body:
            return assignments
        
        # Traverse constructor body for assignments involving the parameter
        for stmt in constructor_node.body:
            if hasattr(stmt, 'expression') and hasattr(stmt.expression, 'expressionl'):
                assignment = stmt.expression
                if hasattr(assignment, 'value') and param_name in str(assignment.value):
                    assignments.append({
                        "target": str(assignment.expressionl) if hasattr(assignment, 'expressionl') else 'unknown',
                        "source": str(assignment.value) if hasattr(assignment, 'value') else 'unknown',
                        "assignment_type": "field_assignment"
                    })
        
        return assignments
    
    def _analyze_setter_methods(self, ast_tree) -> List[Dict]:
        """
        Setter method analysis: Check setter methods for threshold-related parameters
        """
        log.debug("Analyzing setter methods for threshold parameters")
        setter_patterns = []
        
        for path, node in ast_tree.filter(MethodDeclaration):
            method_name = node.name
            
            # Check if method name matches setter patterns
            is_setter = any(re.match(pattern, method_name) for pattern in self.setter_patterns)
            
            if is_setter and node.parameters:
                for param in node.parameters:
                    setter_info = {
                        "type": "setter_method",
                        "method_name": method_name,
                        "parameter_name": param.name,
                        "parameter_type": str(param.type) if hasattr(param.type, 'name') else str(param.type),
                        "assignments": self._extract_setter_assignments(node, param.name)
                    }
                    setter_patterns.append(setter_info)
                    log.debug(f"Found setter method: {method_name}({param.name})")
        
        return setter_patterns
    
    def _extract_setter_assignments(self, method_node, param_name: str) -> List[Dict]:
        """Extract assignment operations in setter method body"""
        assignments = []
        
        if not method_node.body:
            return assignments
        
        for stmt in method_node.body:
            if hasattr(stmt, 'expression'):
                assignment = stmt.expression
                if hasattr(assignment, 'value') and param_name in str(assignment.value):
                    assignments.append({
                        "target": str(assignment.expressionl) if hasattr(assignment, 'expressionl') else 'unknown',
                        "source": param_name,
                        "assignment_type": "setter_assignment"
                    })
        
        return assignments
    
    def _analyze_static_config(self, ast_tree) -> List[Dict]:
        """
        Static configuration file analysis: Detect config file reading operations
        """
        log.debug("Analyzing static configuration file operations")
        config_patterns = []
        
        # Analyze method invocations for config file operations
        for path, node in ast_tree.filter(MethodInvocation):
            if not node.qualifier:
                continue
                
            qualifier_str = str(node.qualifier)
            method_name = node.member
            
            # Check for configuration file reading patterns
            if any(config_type in qualifier_str for config_type in self.config_file_patterns):
                config_info = {
                    "type": "static_config_file",
                    "config_class": qualifier_str,
                    "method_name": method_name,
                    "arguments": [str(arg) for arg in node.arguments] if node.arguments else [],
                    "config_source": self._identify_config_source(node)
                }
                config_patterns.append(config_info)
                log.debug(f"Found config file operation: {qualifier_str}.{method_name}")
        
        # Analyze field declarations for config file references
        for path, node in ast_tree.filter(FieldDeclaration):
            if hasattr(node, 'type') and hasattr(node.type, 'name'):
                type_name = node.type.name
                if any(config_type in type_name for config_type in self.config_file_patterns):
                    for declarator in node.declarators:
                        config_info = {
                            "type": "static_config_field",
                            "field_name": declarator.name,
                            "field_type": type_name,
                            "initializer": str(declarator.initializer) if declarator.initializer else None
                        }
                        config_patterns.append(config_info)
                        log.debug(f"Found config field: {declarator.name} ({type_name})")
        
        return config_patterns
    
    def _identify_config_source(self, method_node) -> str:
        """Identify the source of configuration (file path, resource name, etc.)"""
        if not method_node.arguments:
            return "unknown"
        
        # Try to extract string literals from arguments
        for arg in method_node.arguments:
            if hasattr(arg, 'value') and isinstance(arg.value, str):
                return arg.value
        
        return "dynamic"
    
    def _analyze_dynamic_sources(self, ast_tree) -> List[Dict]:
        """
        Dynamic data source analysis: Detect network/API-based parameter loading
        """
        log.debug("Analyzing dynamic data sources for threshold parameters")
        dynamic_patterns = []
        
        # Analyze method invocations for dynamic method patterns
        for path, node in ast_tree.filter(MethodInvocation):
            method_name = node.member
            
            # Check for dynamic threshold fetching methods
            if method_name in self.dynamic_method_patterns:
                dynamic_info = {
                    "type": "dynamic_method_call",
                    "method_name": method_name,
                    "qualifier": str(node.qualifier) if node.qualifier else "this",
                    "arguments": [str(arg) for arg in node.arguments] if node.arguments else [],
                    "network_source": self._detect_network_source(ast_tree, method_name)
                }
                dynamic_patterns.append(dynamic_info)
                log.debug(f"Found dynamic method call: {method_name}")
        
        # Analyze network-related class usage
        network_usage = self._analyze_network_usage(ast_tree)
        dynamic_patterns.extend(network_usage)
        
        return dynamic_patterns
    
    def _detect_network_source(self, ast_tree, method_name: str) -> Dict[str, Any]:
        """Detect if a method involves network operations"""
        network_indicators = {
            "has_http_client": False,
            "has_url_connection": False,
            "has_api_call": False,
            "network_libraries": []
        }
        
        # Check for network-related imports and usage
        for path, node in ast_tree.filter(MethodInvocation):
            if node.qualifier:
                qualifier_str = str(node.qualifier)
                if any(network_type in qualifier_str for network_type in self.network_patterns):
                    network_indicators["network_libraries"].append(qualifier_str)
                    
                    if "Http" in qualifier_str:
                        network_indicators["has_http_client"] = True
                    if "URL" in qualifier_str:
                        network_indicators["has_url_connection"] = True
                    if "API" in str(node.member) or "api" in str(node.member):
                        network_indicators["has_api_call"] = True
        
        return network_indicators
    
    def _analyze_network_usage(self, ast_tree) -> List[Dict]:
        """Analyze network library usage for parameter fetching"""
        network_patterns = []
        
        for path, node in ast_tree.filter(MethodInvocation):
            if not node.qualifier:
                continue
                
            qualifier_str = str(node.qualifier)
            
            # Check for network library usage
            if any(network_type in qualifier_str for network_type in self.network_patterns):
                network_info = {
                    "type": "network_api_call",
                    "network_class": qualifier_str,
                    "method_name": node.member,
                    "arguments": [str(arg) for arg in node.arguments] if node.arguments else [],
                    "potential_threshold_source": self._is_threshold_related_call(node)
                }
                network_patterns.append(network_info)
                log.debug(f"Found network API call: {qualifier_str}.{node.member}")
        
        return network_patterns
    
    def _is_threshold_related_call(self, method_node) -> bool:
        """Check if a method call is potentially related to threshold configuration"""
        threshold_keywords = [
            "threshold", "limit", "config", "setting", "param", 
            "value", "level", "sensitivity", "trigger"
        ]
        
        method_str = str(method_node).lower()
        return any(keyword in method_str for keyword in threshold_keywords)
    
    def categorize_parameters(self, analysis_results: Dict[str, List[Dict]]) -> Dict[str, Any]:
        """
        Categorize detected parameters by source type and reliability
        """
        categorization = {
            "L1_hardcoded": [],      # Hardcoded in constructor/setter
            "L2_config_file": [],    # From static configuration files  
            "L3_dynamic": [],        # From network/API calls
            "summary": {
                "total_parameters": 0,
                "constructor_params": 0,
                "setter_params": 0,
                "config_file_params": 0,
                "dynamic_params": 0
            }
        }
        
        # Categorize constructor parameters
        for param in analysis_results.get("constructor_analysis", []):
            categorization["L1_hardcoded"].append({
                "source": "constructor",
                "parameter": param["parameter_name"],
                "type": param["parameter_type"],
                "reliability": "high"
            })
            categorization["summary"]["constructor_params"] += 1
        
        # Categorize setter parameters
        for param in analysis_results.get("setter_method_analysis", []):
            categorization["L1_hardcoded"].append({
                "source": "setter",
                "parameter": param["parameter_name"],
                "method": param["method_name"],
                "reliability": "high"
            })
            categorization["summary"]["setter_params"] += 1
        
        # Categorize config file parameters
        for param in analysis_results.get("static_config_analysis", []):
            categorization["L2_config_file"].append({
                "source": "config_file",
                "config_class": param.get("config_class", param.get("field_type", "unknown")),
                "reliability": "medium"
            })
            categorization["summary"]["config_file_params"] += 1
        
        # Categorize dynamic parameters
        for param in analysis_results.get("dynamic_source_analysis", []):
            categorization["L3_dynamic"].append({
                "source": "network_api",
                "method": param.get("method_name", param.get("network_class", "unknown")),
                "reliability": "low"
            })
            categorization["summary"]["dynamic_params"] += 1
        
        categorization["summary"]["total_parameters"] = (
            categorization["summary"]["constructor_params"] +
            categorization["summary"]["setter_params"] +
            categorization["summary"]["config_file_params"] +
            categorization["summary"]["dynamic_params"]
        )
        
        return categorization