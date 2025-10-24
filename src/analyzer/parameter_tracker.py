"""
Dynamic parameter propagation analysis algorithm
Track parameter sources and build parameter propagation graph
Enhanced with field-level sensor data tracking
"""
import os
from typing import Dict, List, Optional, Set, Any
import networkx as nx
import javalang
from javalang.tree import (
    VariableDeclarator, Literal, MemberReference, MethodInvocation,
    ConstructorDeclaration, MethodDeclaration, Assignment
)

from src.utils.logger import log
from src.analyzer.field_tracker import SensorFieldTracker


class ParameterOriginTracker:
    """Enhanced parameter origin tracker with field-level sensor data tracking"""
    
    # Dynamic method name collection
    DYNAMIC_METHODS = {
        "getRemoteConfig", "loadFromAPI", "fetchConfig", "getCloudConfig",
        "loadConfigFromServer", "fetchFromNetwork", "getServerConfig",
        "loadDynamicConfig", "fetchRemoteData", "getNetworkConfig"
    }
    
    # Configuration related types
    CONFIG_TYPES = {
        "Config", "Properties", "Configuration", "Settings",
        "ConfigurationManager", "PreferenceManager"
    }
    
    def __init__(self):
        self.propagation_graph = nx.DiGraph()
        self.variable_origins: Dict[str, Dict[str, Any]] = {}
        self.config_parameters: Dict[str, str] = {}
        # Add field tracker for sensor data
        self.field_tracker = SensorFieldTracker()
    
    def track_parameter_origin(self, ast_tree, config_path: Optional[str] = None) -> nx.DiGraph:
        """
        Track parameter sources and build parameter propagation graph
        Enhanced with field-level sensor data tracking
        
        Args:
            ast_tree: Java AST tree
            config_path: Configuration file path
            
        Returns:
            nx.DiGraph: Parameter propagation graph
        """
        log.debug("Starting to build parameter propagation graph with field-level tracking")
        
        # Reset state
        self.propagation_graph.clear()
        self.variable_origins.clear()
        
        # Parse configuration file
        if config_path and os.path.exists(config_path):
            self.config_parameters = self._parse_config_file(config_path)
            log.debug(f"Loaded configuration file parameters: {len(self.config_parameters)}")
        
        # Analyze variable declarations
        self._analyze_variable_declarations(ast_tree)
        
        # Track external assignments
        self._track_external_assignments(ast_tree)
        
        # Enhanced: Track sensor field-level data flow
        self._track_sensor_field_flow(ast_tree)
        
        log.info(f"Enhanced parameter propagation graph construction completed: {len(self.propagation_graph.nodes)} nodes, "
                f"{len(self.propagation_graph.edges)} edges")
        
        return self.propagation_graph.copy()
    
    def _analyze_variable_declarations(self, ast_tree) -> None:
        """Analyze variable declaration nodes"""
        
        for path, node in ast_tree.filter(VariableDeclarator):
            var_name = node.name
            initializer = node.initializer
            
            if initializer is None:
                continue
            
            # L1 level: literal initialization
            if isinstance(initializer, Literal):
                self.propagation_graph.add_node(var_name, level="L1", value=initializer.value)
                self.variable_origins[var_name] = {
                    "type": "literal",
                    "value": initializer.value,
                    "level": "L1"
                }
                log.debug(f"Found L1 level variable: {var_name} = {initializer.value}")
            
            # L2 level: member reference initialization
            elif isinstance(initializer, MemberReference):
                source = initializer.member
                self.propagation_graph.add_edge(source, var_name)
                self.propagation_graph.nodes[var_name]['level'] = "L2"
                self.variable_origins[var_name] = {
                    "type": "field",
                    "source": source,
                    "level": "L2"
                }
                log.debug(f"Found L2 level variable: {var_name} <- {source}")
            
            # L3级：方法调用初始化
            elif isinstance(initializer, MethodInvocation):
                method_name = initializer.member
                if method_name in self.DYNAMIC_METHODS:
                    self.propagation_graph.add_node(var_name, level="L3")
                    self.variable_origins[var_name] = {
                        "type": "method",
                        "source": method_name,
                        "level": "L3"
                    }
                    log.debug(f"Found L3 level variable: {var_name} <- {method_name}()")
    
    def _track_external_assignments(self, ast_tree) -> None:
        """Track external assignment situations"""
        
        # Constructor parameter passing
        self._track_constructor_assignments(ast_tree)
        
        # Setter method passing
        self._track_setter_assignments(ast_tree)
        
        # Static configuration file passing
        self._track_config_assignments(ast_tree)
        
        # Dynamic API passing
        self._track_dynamic_api_assignments(ast_tree)
    
    def _track_constructor_assignments(self, ast_tree) -> None:
        """Track parameter passing in constructors"""
        
        for path, constructor in ast_tree.filter(ConstructorDeclaration):
            if not constructor.parameters:
                continue
            
            for param in constructor.parameters:
                param_name = param.name
                param_type = param.type.name if hasattr(param.type, 'name') else str(param.type)
                
                # Check if it's a configuration type parameter
                if param_type in self.CONFIG_TYPES:
                    # Find assignments in constructor body
                    if constructor.body:
                        assignments = self._get_all_assignments(constructor.body)
                        for assignment in assignments:
                            if (hasattr(assignment, 'value') and 
                                hasattr(assignment.value, 'member') and
                                assignment.value.member == param_name):
                                
                                target = (assignment.expressionl.selectors[0].member 
                                         if (hasattr(assignment, 'expressionl') and 
                                             hasattr(assignment.expressionl, 'selectors') and
                                             assignment.expressionl.selectors and
                                             hasattr(assignment.expressionl.selectors[0], 'member'))
                                         else 'unknown')
                                
                                self.propagation_graph.add_edge(param_name, target)
                                self.propagation_graph.nodes[target]['level'] = "L3"
                                
                                log.debug(f"Constructor passing: {param_name} -> {target}")
    
    def _track_setter_assignments(self, ast_tree) -> None:
        """Track parameter passing in Setter methods"""
        
        for path, method in ast_tree.filter(MethodDeclaration):
            if not method.name.startswith('set') or not method.body:
                continue
            
            # Get setter method parameters
            if method.parameters:
                param = method.parameters[0]
                param_name = param.name
                
                # Find assignments in method body
                assignments = self._get_all_assignments(method.body)
                for assignment in assignments:
                    if isinstance(assignment.value, MemberReference):
                        target = (assignment.expressionl.selectors[0].member 
                                 if (hasattr(assignment, 'expressionl') and 
                                     hasattr(assignment.expressionl, 'selectors') and
                                     assignment.expressionl.selectors and
                                     hasattr(assignment.expressionl.selectors[0], 'member'))
                                 else 'unknown')
                        
                        self.propagation_graph.add_edge(param_name, target)
                        self.propagation_graph.nodes[target]['level'] = "L3"
                        
                        log.debug(f"Setter passing: {param_name} -> {target}")
    
    def _track_config_assignments(self, ast_tree) -> None:
        """Track static configuration file passing"""
        
        for path, call in ast_tree.filter(MethodInvocation):
            if call.member in {"load", "getProperty", "getString", "getInt", "getFloat"}:
                # Extract configuration key
                key = "unknown"
                if call.arguments and hasattr(call.arguments[0], 'value'):
                    key = call.arguments[0].value
                
                # Create node
                node_name = f"Line{call.position.line}" if call.position else f"Config_{key}"
                self.propagation_graph.add_edge(key, node_name)
                self.propagation_graph.nodes[node_name]['level'] = "L2"
                
                log.debug(f"Configuration file passing: {key} -> {node_name}")
    
    def _track_dynamic_api_assignments(self, ast_tree) -> None:
        """Track dynamic API passing"""
        
        for path, call in ast_tree.filter(MethodInvocation):
            if call.member in self.DYNAMIC_METHODS:
                node_name = f"Line{call.position.line}" if call.position else f"API_{call.member}"
                api_source = f"API:{call.member}"
                
                self.propagation_graph.add_edge(api_source, node_name)
                self.propagation_graph.nodes[node_name]['level'] = "L3"
                
                log.debug(f"Dynamic API passing: {api_source} -> {node_name}")
    
    def _track_sensor_field_flow(self, ast_tree) -> None:
        """Track sensor data flow through object fields"""
        try:
            # Use field tracker to analyze sensor field flows
            field_graph = self.field_tracker.track_sensor_field_flow(ast_tree)
            
            # Merge field graph into main propagation graph
            for node, data in field_graph.nodes(data=True):
                self.propagation_graph.add_node(node, **data)
            
            for source, target, data in field_graph.edges(data=True):
                self.propagation_graph.add_edge(source, target, **data)
            
            # Add sensor field information to variable origins
            for field_name, field_info in self.field_tracker.sensor_fields.items():
                self.variable_origins[field_name] = {
                    "type": "sensor_field",
                    "field_type": field_info["field_type"],
                    "level": "L2",  # Sensor fields are typically L2 level
                    "sensor_type": field_info["type"]
                }
            
            log.info(f"Integrated {len(field_graph.nodes)} sensor field nodes and {len(field_graph.edges)} field edges")
            
        except Exception as e:
            log.warning(f"Field-level tracking failed: {e}")
    
    def _get_all_assignments(self, node) -> List[Assignment]:
        """Recursively get all assignment statements in node"""
        assignments = []
        
        if isinstance(node, list):
            for sub_node in node:
                assignments.extend(self._get_all_assignments(sub_node))
        elif isinstance(node, Assignment):
            assignments.append(node)
        elif hasattr(node, 'children'):
            for child in node.children:
                if child is not None:
                    assignments.extend(self._get_all_assignments(child))
        
        return assignments
    
    def _parse_config_file(self, config_path: str) -> Dict[str, str]:
        """Parse configuration file"""
        params = {}
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    
                    # Skip comments and empty lines
                    if not line or line.startswith('#') or line.startswith('!'):
                        continue
                    
                    # Parse key-value pairs
                    if '=' in line:
                        key, _, value = line.partition('=')
                        params[key.strip()] = value.strip()
                        
        except Exception as e:
            log.warning(f"Failed to parse configuration file {config_path}: {e}")
        
        return params
    
    def get_parameter_levels(self) -> Dict[str, List[str]]:
        """Get parameter list of different levels"""
        levels = {"L1": [], "L2": [], "L3": []}
        
        for node, data in self.propagation_graph.nodes(data=True):
            level = data.get('level', 'unknown')
            if level in levels:
                levels[level].append(node)
        
        return levels
    
    def get_propagation_paths(self, target_var: str) -> List[List[str]]:
        """Get propagation paths to target variable"""
        paths = []
        
        # Find all paths to target variable
        for source in self.propagation_graph.nodes():
            if source != target_var:
                try:
                    if nx.has_path(self.propagation_graph, source, target_var):
                        shortest_path = nx.shortest_path(self.propagation_graph, source, target_var)
                        paths.append(shortest_path)
                except nx.NetworkXNoPath:
                    continue
        
        return paths
    
    def visualize_graph(self, output_path: Optional[str] = None) -> None:
        """Visualize parameter propagation graph"""
        try:
            import matplotlib.pyplot as plt
            
            plt.figure(figsize=(12, 8))
            pos = nx.spring_layout(self.propagation_graph)
            
            # Set colors based on level
            node_colors = []
            for node in self.propagation_graph.nodes():
                level = self.propagation_graph.nodes[node].get('level', 'unknown')
                if level == 'L1':
                    node_colors.append('lightblue')
                elif level == 'L2':
                    node_colors.append('lightgreen')
                elif level == 'L3':
                    node_colors.append('lightcoral')
                else:
                    node_colors.append('lightgray')
            
            nx.draw(self.propagation_graph, pos, 
                   node_color=node_colors, 
                   with_labels=True, 
                   node_size=1500,
                   font_size=8,
                   arrows=True)
            
            plt.title("Parameter Propagation Graph")
            
            if output_path:
                plt.savefig(output_path)
                log.info(f"Parameter propagation graph saved to: {output_path}")
            else:
                plt.show()
                
        except ImportError:
            log.warning("matplotlib not installed, cannot generate visualization")

    def get_enhanced_parameter_summary(self) -> Dict[str, Any]:
        """Get enhanced parameter summary including field-level analysis"""
        summary = {
            "parameter_levels": self.get_parameter_levels(),
            "sensor_fields": self.field_tracker.sensor_fields,
            "field_accesses": self.field_tracker.field_accesses,
            "cross_method_flows": self.field_tracker.cross_method_flows,
            "field_summary": self.field_tracker.get_sensor_field_summary()
        }
        
        return summary


def track_parameters_from_code(code: str, config_path: Optional[str] = None) -> nx.DiGraph:
    """
    Track parameter propagation from Java code
    
    Args:
        code: Java source code
        config_path: Configuration file path
        
    Returns:
        nx.DiGraph: Parameter propagation graph
    """
    try:
        tree = javalang.parse.parse(code)
        tracker = ParameterOriginTracker()
        return tracker.track_parameter_origin(tree, config_path)
    except Exception as e:
        log.error(f"Parameter tracking failed: {e}")
        return nx.DiGraph()



