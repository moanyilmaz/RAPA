"""
Threshold condition parsing algorithm
Extract sensor threshold judgment logic from AST
"""
from typing import List, Dict, Optional, Any, Union
import javalang
from javalang.tree import (
    IfStatement, BinaryOperation, Literal, 
    MemberReference, LocalVariableDeclaration, VariableDeclarator
)

from src.utils.logger import log


class ThresholdCondition:
    """Threshold condition data structure"""
    
    def __init__(self, variable_name: str, operator: str, value: Union[float, int], 
                 variable_source: str = "unknown"):
        self.variable_name = variable_name
        self.operator = operator
        self.value = value
        self.variable_source = variable_source
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "variable_name": self.variable_name,
            "operator": self.operator,
            "value": self.value,
            "variable_source": self.variable_source
        }
    
    def __repr__(self) -> str:
        return f"ThresholdCondition({self.variable_name} {self.operator} {self.value})"


class ThresholdExtractor:
    """Threshold condition parser"""
    
    # Operator reverse mapping table
    OPERATOR_REVERSE_MAP = {
        ">": "<",
        ">=": "<=", 
        "<": ">",
        "<=": ">=",
        "==": "==",
        "!=": "!="
    }
    
    # Sensor-related variable name patterns
    SENSOR_VARIABLE_PATTERNS = [
        r".*[Aa]cc.*",  # acceleration related
        r".*[Ss]ensor.*",  # sensor related
        r".*[Vv]alue.*",  # value related
        r".*[Tt]hreshold.*",  # threshold related
        r".*[Ff]orce.*",  # force related
        r".*[Ss]peed.*",  # speed related
        r".*[Mm]agnitude.*",  # magnitude related
        r".*[Aa]mplitude.*",  # amplitude related
        r".*[Ii]ntensity.*",  # intensity related
        r".*[Ll]evel.*",  # level related
        r"x|y|z|X|Y|Z",  # axis variables
        r"f\d+",  # f11, f12, f13 style variables
        r"d\d+",  # d11, d12 style variables
        r"i\d+"   # i11, i12 style variables
    ]
    
    def __init__(self):
        self.threshold_list: List[ThresholdCondition] = []
        self.variable_sources: Dict[str, str] = {}
    
    def extract_thresholds(self, ast_tree) -> List[ThresholdCondition]:
        """
        Extract threshold conditions from AST
        
        Args:
            ast_tree: Java AST tree
            
        Returns:
            List[ThresholdCondition]: List of extracted threshold conditions
        """
        log.debug("Starting threshold condition extraction")
        
        self.threshold_list.clear()
        self.variable_sources.clear()
        
        # First collect variable source information
        self._collect_variable_sources(ast_tree)
        
        # Traverse all if statement nodes
        for path, if_node in ast_tree.filter(IfStatement):
            self._analyze_if_condition(if_node.condition)
        
        log.info(f"Threshold condition extraction completed, found {len(self.threshold_list)} conditions")
        return self.threshold_list.copy()
    
    def _collect_variable_sources(self, ast_tree) -> None:
        """Collect variable source information"""
        
        # Collect local variable declarations
        for path, var_decl in ast_tree.filter(LocalVariableDeclaration):
            if var_decl.declarators:
                for declarator in var_decl.declarators:
                    if isinstance(declarator, VariableDeclarator):
                        var_name = declarator.name
                        if declarator.initializer:
                            if isinstance(declarator.initializer, Literal):
                                self.variable_sources[var_name] = "literal"
                            elif isinstance(declarator.initializer, MemberReference):
                                self.variable_sources[var_name] = "member_reference"
                            else:
                                self.variable_sources[var_name] = "expression"
                        else:
                            self.variable_sources[var_name] = "parameter"
    
    def _analyze_if_condition(self, condition) -> None:
        """Analyze if statement condition expression"""
        
        if not isinstance(condition, BinaryOperation):
            return
        
        left = condition.operandl
        operator = condition.operator
        right = condition.operandr
        
        # Pattern 1: variable-value mode (variable op literal)
        if self._is_sensor_variable(left) and self._is_literal_value(right):
            var_name = self._extract_variable_name(left)
            value = self._extract_literal_value(right)
            source = self.variable_sources.get(var_name, "unknown")
            
            threshold = ThresholdCondition(var_name, operator, value, source)
            self.threshold_list.append(threshold)
            log.debug(f"Found variable-value pattern threshold: {threshold}")
        
        # Pattern 2: value-variable reverse mode (literal op variable)
        elif self._is_literal_value(left) and self._is_sensor_variable(right):
            var_name = self._extract_variable_name(right)
            value = self._extract_literal_value(left)
            reversed_operator = self.OPERATOR_REVERSE_MAP.get(operator, operator)
            source = self.variable_sources.get(var_name, "unknown")
            
            threshold = ThresholdCondition(var_name, reversed_operator, value, source)
            self.threshold_list.append(threshold)
            log.debug(f"Found value-variable reverse pattern threshold: {threshold}")
        
        # Recursively process compound conditions
        if hasattr(condition, 'operandl'):
            self._analyze_if_condition(condition.operandl)
        if hasattr(condition, 'operandr'):
            self._analyze_if_condition(condition.operandr)
    
    def _is_sensor_variable(self, node) -> bool:
        """Check if it is a sensor-related variable"""
        
        if isinstance(node, MemberReference):
            var_name = node.member
        elif hasattr(node, 'name'):
            var_name = node.name
        else:
            return False
        
        # Check if it matches the sensor variable pattern
        import re
        for pattern in self.SENSOR_VARIABLE_PATTERNS:
            if re.match(pattern, var_name):
                return True
        
        return False
    
    def _is_literal_value(self, node) -> bool:
        """Check if it is a literal value"""
        return isinstance(node, Literal) and node.value is not None
    
    def _extract_variable_name(self, node) -> str:
        """Extract variable name"""
        if isinstance(node, MemberReference):
            return node.member
        elif hasattr(node, 'name'):
            return node.name
        else:
            return "unknown"
    
    def _extract_literal_value(self, node) -> Union[float, int]:
        """Extract literal value"""
        if isinstance(node, Literal):
            value = node.value
            try:
                # Try to convert to numeric value
                if '.' in str(value):
                    return float(value)
                else:
                    return int(value)
            except (ValueError, TypeError):
                return 0
        return 0
    
    def get_threshold_summary(self) -> Dict[str, Any]:
        """Get threshold condition summary"""
        if not self.threshold_list:
            return {"count": 0, "thresholds": []}
        
        summary = {
            "count": len(self.threshold_list),
            "thresholds": [condition.to_dict() for condition in self.threshold_list],
            "variable_names": list(set(condition.variable_name for condition in self.threshold_list)),
            "operators": list(set(condition.operator for condition in self.threshold_list)),
            "values": list(set(condition.value for condition in self.threshold_list))
        }
        
        return summary


def extract_thresholds_from_code(code: str) -> List[ThresholdCondition]:
    """
    Extract threshold conditions from Java code
    
    Args:
        code: Java source code
        
    Returns:
        List[ThresholdCondition]: Threshold condition list
    """
    try:
        tree = javalang.parse.parse(code)
        extractor = ThresholdExtractor()
        return extractor.extract_thresholds(tree)
    except Exception as e:
        log.error(f"Code parsing failed: {e}")
        return []



