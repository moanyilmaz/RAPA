"""
Field-level data source tracking for sensor data propagation
Enhanced tracking for sensor data flow through object fields
"""
import os
from typing import Dict, List, Optional, Set, Any, Tuple
import networkx as nx
import javalang
from javalang.tree import (
    VariableDeclarator, Literal, MemberReference, MethodInvocation,
    ConstructorDeclaration, MethodDeclaration, Assignment, FieldDeclaration,
    ArraySelector, BinaryOperation, IfStatement, WhileStatement, ForStatement
)

from src.utils.logger import log


class SensorFieldTracker:
    """Enhanced field-level sensor data tracker"""
    
    # Sensor-related field patterns
    SENSOR_FIELD_PATTERNS = {
        "values": ["values", "data", "sensorData", "accelData", "gyroData"],
        "event": ["event", "sensorEvent", "accelEvent", "gyroEvent"],
        "threshold": ["threshold", "sensorThreshold", "accelThreshold", "shakeThreshold"],
        "listener": ["listener", "sensorListener", "accelListener", "shakeListener"]
    }
    
    # Sensor data access patterns
    SENSOR_ACCESS_PATTERNS = [
        r"event\.values\[\d+\]",  # event.values[0], event.values[1], etc.
        r"event\.values\[[xyz]\]",  # event.values[x], event.values[y], etc.
        r"\.values\[\d+\]",  # .values[0], .values[1], etc.
        r"\.getValues\(\)",  # .getValues() method calls
        r"\.getAcceleration\(\)",  # .getAcceleration() method calls
    ]
    
    # Sensor event types
    SENSOR_EVENT_TYPES = {
        "SensorEvent", "AccelerometerEvent", "GyroscopeEvent", 
        "SensorData", "AccelerationData", "MotionData"
    }
    
    def __init__(self):
        self.field_propagation_graph = nx.DiGraph()
        self.sensor_fields: Dict[str, Dict[str, Any]] = {}
        self.field_accesses: List[Dict[str, Any]] = []
        self.cross_method_flows: List[Dict[str, Any]] = []
        
    def track_sensor_field_flow(self, ast_tree) -> nx.DiGraph:
        """
        Track sensor data flow through object fields
        
        Args:
            ast_tree: Java AST tree
            
        Returns:
            nx.DiGraph: Field-level propagation graph
        """
        log.debug("Starting sensor field-level data flow tracking")
        
        # Reset state
        self.field_propagation_graph.clear()
        self.sensor_fields.clear()
        self.field_accesses.clear()
        self.cross_method_flows.clear()
        
        # Step 1: Identify sensor-related fields
        self._identify_sensor_fields(ast_tree)
        
        # Step 2: Track field assignments and accesses
        self._track_field_assignments(ast_tree)
        
        # Step 3: Track cross-method field flows
        self._track_cross_method_flows(ast_tree)
        
        # Step 4: Track array element accesses
        self._track_array_element_accesses(ast_tree)
        
        # Step 5: Build propagation graph
        self._build_field_propagation_graph()
        
        log.info(f"Field-level tracking completed: {len(self.field_propagation_graph.nodes)} nodes, "
                f"{len(self.field_propagation_graph.edges)} edges")
        
        return self.field_propagation_graph.copy()
    
    def _identify_sensor_fields(self, ast_tree) -> None:
        """Identify sensor-related field declarations"""
        
        for path, field_decl in ast_tree.filter(FieldDeclaration):
            field_type = field_decl.type.name if hasattr(field_decl.type, 'name') else str(field_decl.type)
            
            # Check if it's a sensor event type
            if field_type in self.SENSOR_EVENT_TYPES:
                for declarator in field_decl.declarators:
                    field_name = declarator.name
                    self.sensor_fields[field_name] = {
                        "type": "sensor_event",
                        "field_type": field_type,
                        "declaration_line": field_decl.position.line if field_decl.position else 0
                    }
                    log.debug(f"Found sensor event field: {field_name} ({field_type})")
            
            # Check for sensor data arrays
            elif "[]" in str(field_type) or "Array" in field_type:
                for declarator in field_decl.declarators:
                    field_name = declarator.name
                    if any(pattern in field_name.lower() for patterns in self.SENSOR_FIELD_PATTERNS.values() 
                           for pattern in patterns):
                        self.sensor_fields[field_name] = {
                            "type": "sensor_data_array",
                            "field_type": field_type,
                            "declaration_line": field_decl.position.line if field_decl.position else 0
                        }
                        log.debug(f"Found sensor data array field: {field_name} ({field_type})")
    
    def _track_field_assignments(self, ast_tree) -> None:
        """Track field assignments and accesses"""
        
        for path, assignment in ast_tree.filter(Assignment):
            try:
                # Handle field assignments: this.field = value
                if (hasattr(assignment, 'expressionl') and 
                    hasattr(assignment.expressionl, 'selectors') and
                    assignment.expressionl.selectors):
                    
                    # Safely get field name
                    if hasattr(assignment.expressionl.selectors[0], 'member'):
                        target_field = assignment.expressionl.selectors[0].member
                    else:
                        # Handle array selector case
                        continue
                    
                    # Check if target is a sensor field
                    if target_field in self.sensor_fields:
                        source_value = self._extract_assignment_source(assignment.value)
                        
                        self.field_accesses.append({
                            "type": "field_assignment",
                            "target_field": target_field,
                            "source": source_value,
                            "line": assignment.position.line if assignment.position else 0,
                            "context": self._get_context(path)
                        })
                        
                        log.debug(f"Field assignment: {target_field} = {source_value}")
                
                # Handle array element assignments: this.field[index] = value
                elif (hasattr(assignment, 'expressionl') and 
                      hasattr(assignment.expressionl, 'selectors') and
                      len(assignment.expressionl.selectors) > 1):
                    
                    # Safely get field name - check if first selector has member attribute
                    first_selector = assignment.expressionl.selectors[0]
                    if hasattr(first_selector, 'member'):
                        field_name = first_selector.member
                    else:
                        # Skip if we can't get the field name safely
                        continue
                        
                    if field_name in self.sensor_fields:
                        # Safely get array index
                        try:
                            index = self._extract_array_index(assignment.expressionl.selectors[1])
                        except Exception:
                            index = "unknown"
                            
                        source_value = self._extract_assignment_source(assignment.value)
                        
                        self.field_accesses.append({
                            "type": "array_element_assignment",
                            "target_field": field_name,
                            "index": index,
                            "source": source_value,
                            "line": assignment.position.line if assignment.position else 0,
                            "context": self._get_context(path)
                        })
                        
                        log.debug(f"Array element assignment: {field_name}[{index}] = {source_value}")
                        
            except Exception as e:
                log.warning(f"Error tracking field assignment: {e}")
                # Add more detailed error information for debugging
                log.debug(f"Assignment details: {assignment}")
                if hasattr(assignment, 'expressionl'):
                    log.debug(f"Expression left: {assignment.expressionl}")
                    if hasattr(assignment.expressionl, 'selectors'):
                        log.debug(f"Selectors: {assignment.expressionl.selectors}")
                        for i, selector in enumerate(assignment.expressionl.selectors):
                            log.debug(f"Selector {i}: {type(selector)} - {selector}")
    
    def _track_cross_method_flows(self, ast_tree) -> None:
        """Track sensor data flows across different methods"""
        
        method_sensor_fields = {}
        
        # First pass: collect sensor field usage in each method
        for path, method in ast_tree.filter(MethodDeclaration):
            method_name = method.name
            method_sensor_fields[method_name] = []
            
            # Find sensor field reads and writes in this method
            for access in self.field_accesses:
                if access.get("context", {}).get("method") == method_name:
                    method_sensor_fields[method_name].append(access)
        
        # Second pass: analyze cross-method flows
        for method_name, accesses in method_sensor_fields.items():
            if not isinstance(accesses, list):
                continue
            for access in accesses:
                if access["type"] == "field_assignment":
                    # Find where this field is read in other methods
                    for other_method, other_accesses in method_sensor_fields.items():
                        if other_method != method_name and isinstance(other_accesses, list):
                            for other_access in other_accesses:
                                if (other_access["type"] == "field_read" and 
                                    other_access["target_field"] == access["target_field"]):
                                    
                                    self.cross_method_flows.append({
                                        "write_method": method_name,
                                        "read_method": other_method,
                                        "field": access["target_field"],
                                        "write_line": access["line"],
                                        "read_line": other_access["line"]
                                    })
                                    
                                    log.debug(f"Cross-method flow: {method_name} -> {other_method} "
                                            f"via {access['target_field']}")
    
    def _track_array_element_accesses(self, ast_tree) -> None:
        """Track array element accesses (e.g., event.values[0])"""
        
        for path, node in ast_tree.filter(MemberReference):
            try:
                # Check if this is an array access
                if (hasattr(node, 'selectors') and node.selectors and 
                    len(node.selectors) > 1):
                    
                    field_name = node.member
                    if field_name in self.sensor_fields:
                        index = self._extract_array_index(node.selectors[1])
                        
                        self.field_accesses.append({
                            "type": "array_element_read",
                            "target_field": field_name,
                            "index": index,
                            "line": node.position.line if node.position else 0,
                            "context": self._get_context(path)
                        })
                        
                        log.debug(f"Array element read: {field_name}[{index}]")
                
                # Check for direct field access
                elif node.member in self.sensor_fields:
                    self.field_accesses.append({
                        "type": "field_read",
                        "target_field": node.member,
                        "line": node.position.line if node.position else 0,
                        "context": self._get_context(path)
                    })
                    
                    log.debug(f"Field read: {node.member}")
                    
            except Exception as e:
                log.warning(f"Error tracking array element access: {e}")
    
    def _build_field_propagation_graph(self) -> None:
        """Build the field-level propagation graph"""
        
        # Add sensor field nodes
        for field_name, field_info in self.sensor_fields.items():
            self.field_propagation_graph.add_node(field_name, 
                                                type=field_info["type"],
                                                field_type=field_info["field_type"])
        
        # Add field access edges
        for access in self.field_accesses:
            if access["type"] == "field_assignment":
                source = access["source"]
                target = access["target_field"]
                
                self.field_propagation_graph.add_edge(source, target, 
                                                    type="assignment",
                                                    line=access["line"])
            
            elif access["type"] == "array_element_assignment":
                source = access["source"]
                target = f"{access['target_field']}[{access['index']}]"
                
                self.field_propagation_graph.add_edge(source, target,
                                                    type="array_assignment",
                                                    line=access["line"])
        
        # Add cross-method flow edges
        for flow in self.cross_method_flows:
            source = f"{flow['write_method']}:{flow['field']}"
            target = f"{flow['read_method']}:{flow['field']}"
            
            self.field_propagation_graph.add_edge(source, target,
                                                type="cross_method_flow",
                                                write_line=flow["write_line"],
                                                read_line=flow["read_line"])
    
    def _extract_assignment_source(self, value_node) -> str:
        """Extract the source of an assignment"""
        if isinstance(value_node, Literal):
            return f"literal:{value_node.value}"
        elif isinstance(value_node, MemberReference):
            return f"field:{value_node.member}"
        elif isinstance(value_node, MethodInvocation):
            return f"method:{value_node.member}"
        else:
            return "unknown"
    
    def _extract_array_index(self, selector) -> str:
        """Extract array index from selector"""
        try:
            if hasattr(selector, 'value'):
                return str(selector.value)
            elif hasattr(selector, 'member'):
                return selector.member
            elif hasattr(selector, 'index'):
                return str(selector.index)
            else:
                return "unknown"
        except Exception as e:
            log.debug(f"Error extracting array index: {e}")
            return "unknown"
    
    def _get_context(self, path) -> Dict[str, Any]:
        """Get context information from AST path"""
        context = {}
        
        # Find the containing method
        for node in reversed(path):
            if isinstance(node, MethodDeclaration):
                context["method"] = node.name
                context["class"] = self._find_containing_class(path)
                break
        
        return context
    
    def _find_containing_class(self, path) -> str:
        """Find the containing class name"""
        for node in reversed(path):
            if hasattr(node, 'name'):
                return node.name
        return "unknown"
    
    def get_sensor_field_summary(self) -> Dict[str, Any]:
        """Get summary of sensor field tracking results"""
        summary = {
            "total_sensor_fields": len(self.sensor_fields),
            "total_field_accesses": len(self.field_accesses),
            "cross_method_flows": len(self.cross_method_flows),
            "sensor_fields": self.sensor_fields,
            "field_access_types": {},
            "propagation_paths": []
        }
        
        # Count access types
        for access in self.field_accesses:
            if isinstance(access, dict) and "type" in access:
                access_type = access["type"]
                summary["field_access_types"][access_type] = summary["field_access_types"].get(access_type, 0) + 1
        
        # Find propagation paths to sensitive operations
        sensitive_operations = self._find_sensitive_operations()
        for operation in sensitive_operations:
            paths = self._find_paths_to_operation(operation)
            if isinstance(paths, list):
                summary["propagation_paths"].extend(paths)
            else:
                summary["propagation_paths"].append(paths)
        
        return summary
    
    def _find_sensitive_operations(self) -> List[str]:
        """Find sensitive operations that might leak sensor data"""
        sensitive_ops = []
        
        # Look for network operations, file writes, etc.
        for node, data in self.field_propagation_graph.nodes(data=True):
            if any(op in str(node).lower() for op in ["send", "upload", "write", "log", "print"]):
                sensitive_ops.append(node)
        
        return sensitive_ops
    
    def _find_paths_to_operation(self, operation: str) -> List[List[str]]:
        """Find all paths leading to a sensitive operation"""
        paths = []
        
        try:
            for source in self.field_propagation_graph.nodes():
                if source != operation:
                    try:
                        if nx.has_path(self.field_propagation_graph, source, operation):
                            path = nx.shortest_path(self.field_propagation_graph, source, operation)
                            if isinstance(path, list):
                                paths.append(path)
                    except (nx.NetworkXNoPath, nx.NodeNotFound):
                        continue
        except Exception as e:
            log.debug(f"Error finding paths to operation {operation}: {e}")
        
        return paths


def track_sensor_field_flow_from_code(code: str) -> Tuple[nx.DiGraph, Dict[str, Any]]:
    """
    Track sensor field-level data flow from Java code
    
    Args:
        code: Java source code
        
    Returns:
        Tuple[nx.DiGraph, Dict[str, Any]]: Field propagation graph and summary
    """
    try:
        tree = javalang.parse.parse(code)
        tracker = SensorFieldTracker()
        graph = tracker.track_sensor_field_flow(tree)
        summary = tracker.get_sensor_field_summary()
        return graph, summary
    except Exception as e:
        log.error(f"Sensor field tracking failed: {e}")
        return nx.DiGraph(), {}


 