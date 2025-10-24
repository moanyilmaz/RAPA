"""
Large Language Model Analysis Module
Use LLM for intelligent analysis of sensor code
"""
import json
from typing import Dict, List, Any, Optional
from openai import OpenAI
import networkx as nx

from src.utils.logger import log
from config.settings import DASHSCOPE_API_KEY, DASHSCOPE_BASE_URL, MODEL_NAME, MAX_RETRY_ATTEMPTS


class LLMAnalyzer:
    """LLM Analyzer"""
    
    def __init__(self):
        self.client = OpenAI(
            api_key=DASHSCOPE_API_KEY,
            base_url=DASHSCOPE_BASE_URL,
        )
    
    def analyze_shake_pattern(self,
                            code_snippet: str,
                            thresholds: Dict[str, float],
                            external_params: Dict[str, str],
                            dynamic_sources: List[str],
                            call_graph: nx.DiGraph,
                            param_origin: Dict[str, Dict],
                            field_tracking: Dict[str, Any] = None,
                            shake_methods: List[Dict[str, Any]] = None,
                            threshold_propagation: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Analyze shake pattern using LLM with enhanced field-level tracking information
        
        Args:
            code_snippet: Java code snippet
            thresholds: Threshold information
            external_params: External parameter information
            dynamic_sources: Dynamic data sources
            call_graph: Call graph
            param_origin: Parameter origin information
            field_tracking: Enhanced field-level tracking information
            shake_methods: Shake-to-ad specific method fragments
            threshold_propagation: Threshold propagation information
            
        Returns:
            Dict[str, Any]: Analysis result
        """
        log.debug("Starting LLM shake pattern analysis with enhanced field-level tracking")
        
        log.info("=" * 60)
        log.info("ENHANCED ANALYSIS PARAMETERS:")
        log.info("=" * 60)
        log.info(f"Code snippet length: {len(code_snippet)} characters")
        log.info(f"Thresholds: {json.dumps(thresholds, ensure_ascii=False, indent=2)}")
        log.info(f"External params: {json.dumps(external_params, ensure_ascii=False, indent=2)}")
        log.info(f"Dynamic sources: {json.dumps(dynamic_sources, ensure_ascii=False, indent=2)}")
        log.info(f"Call graph edges: {len(call_graph.edges())} edges")
        log.info(f"Parameter origin nodes: {len(param_origin)} nodes")
        
        # Enhanced field-level tracking information
        if field_tracking:
            log.info(f"Field tracking - Sensor fields: {len(field_tracking.get('sensor_fields', {}))}")
            log.info(f"Field tracking - Field accesses: {len(field_tracking.get('field_accesses', []))}")
            log.info(f"Field tracking - Cross-method flows: {len(field_tracking.get('cross_method_flows', []))}")
        
        if shake_methods:
            log.info(f"Shake methods found: {len(shake_methods)}")
            for method in shake_methods:
                log.info(f"  - {method.get('method_name', 'unknown')} (shake: {method.get('is_shake_handler', False)}, ad: {method.get('is_ad_trigger', False)})")
        
        if threshold_propagation:
            log.info(f"Threshold propagation - Found: {len(threshold_propagation.get('thresholds_found', []))}")
            log.info(f"Threshold propagation - Conditions: {len(threshold_propagation.get('threshold_conditions', []))}")
        
        log.info("=" * 60)
        
        # Build enhanced analysis prompt
        prompt = self._build_enhanced_analysis_prompt(
            code_snippet, thresholds, external_params,
            dynamic_sources, call_graph, param_origin,
            field_tracking, shake_methods, threshold_propagation
        )
        
        # Call LLM for analysis
        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                response = self._call_llm(prompt)
                result = self._parse_llm_response(response)
                
                if result:
                    log.success("Enhanced LLM analysis completed")
                    return result
                else:
                    log.warning(f"LLM analysis result parsing failed, attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}")
                    
            except Exception as e:
                log.error(f"LLM call failed, attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}: {e}")
        
        log.error("LLM analysis failed, returning default result")
        return self._get_default_result()
    
    def _build_enhanced_analysis_prompt(self,
                                      code_snippet: str,
                                      thresholds: Dict[str, float],
                                      external_params: Dict[str, str],
                                      dynamic_sources: List[str],
                                      call_graph: nx.DiGraph,
                                      param_origin: Dict[str, Dict],
                                      field_tracking: Dict[str, Any] = None,
                                      shake_methods: List[Dict[str, Any]] = None,
                                      threshold_propagation: Dict[str, Any] = None) -> str:
        """Build enhanced analysis prompt with field-level tracking information"""
        
        # Serialize basic analysis clues
        thr_info = json.dumps(thresholds, ensure_ascii=False)
        ext_info = json.dumps(external_params, ensure_ascii=False)
        dyn_info = json.dumps(dynamic_sources, ensure_ascii=False)
        cg_edges = list(call_graph.edges())
        cg_info = json.dumps({'edges': cg_edges}, ensure_ascii=False)
        po_info = json.dumps(param_origin, ensure_ascii=False)
        
        # Enhanced field-level tracking information
        field_info = ""
        if field_tracking:
            field_info = f"""
## Field-Level Tracking Information:
- Number of sensor fields: {len(field_tracking.get('sensor_fields', {}))}
- Field access count: {len(field_tracking.get('field_accesses', []))}
- Cross-method data flows: {len(field_tracking.get('cross_method_flows', []))}
- Sensor field details: {json.dumps(field_tracking.get('sensor_fields', {}), ensure_ascii=False, indent=2)}
- Field access details: {json.dumps(field_tracking.get('field_accesses', [])[:5], ensure_ascii=False, indent=2)}
"""
        
        # Shake method fragments
        shake_info = ""
        if shake_methods:
            shake_method_details = []
            for method in shake_methods:
                shake_method_details.append({
                    "method_name": method.get('method_name', 'unknown'),
                    "is_shake_handler": method.get('is_shake_handler', False),
                    "is_ad_trigger": method.get('is_ad_trigger', False),
                    "line_start": method.get('line_start', 0),
                    "method_content": method.get('method_content', '')[:200] + "..." if len(method.get('method_content', '')) > 200 else method.get('method_content', '')
                })
            shake_info = f"""
## Shake-Related Method Fragments:
{json.dumps(shake_method_details, ensure_ascii=False, indent=2)}
"""
        
        # Threshold propagation information
        threshold_info = ""
        if threshold_propagation:
            threshold_info = f"""
## Threshold Propagation Information:
- Thresholds found: {threshold_propagation.get('thresholds_found', [])}
- Threshold usage conditions: {json.dumps(threshold_propagation.get('threshold_conditions', []), ensure_ascii=False, indent=2)}
- Threshold assignments: {json.dumps(threshold_propagation.get('threshold_usage', {}), ensure_ascii=False, indent=2)}
"""
        
        prompt = f"""
Please analyze the following decompiled Java code snippet from an Android application and determine whether there exists a clear sensor-based shake-to-ad trigger rule.

## Code Snippet:
```java
{code_snippet}
```

## Analysis Requirements:
1. If there is no clear shake-to-ad rule, output "No explicit rule" in the "trigger_condition_description" field
2. If a clear rule exists, analyze the following dimensions in detail:
   - Variable form (acceleration m/s², angular velocity rad/s, attitude angle, etc.)
   - Time interval requirement
   - Trigger count threshold
   - Direction requirement (X, Y, Z axis or resultant acceleration)
   - Specific threshold value
   - Trigger condition description

## Basic Analysis Clues:
- Threshold information: {thr_info}
- External parameter information: {ext_info}
- Dynamic data sources: {dyn_info}
- Call graph edges: {cg_info}
- Parameter origin: {po_info}

{field_info}
{shake_info}
{threshold_info}

## Output Format:
Please strictly output in the following JSON format without any additional explanation or description:

{{
    "variable_form": "string or null",
    "time_interval_requirement": "string or null", 
    "trigger_count_threshold": "string or null",
    "direction_requirement": "string or null",
    "specific_threshold_value": "string or null",
    "trigger_condition_description": "string"
}}
"""
        
        return prompt
    
    def _call_llm(self, prompt: str) -> str:
        """Call LLM API"""
        
        response = self.client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    'role': 'system',
                    'content': 'You are a professional Android malware analysis expert specializing in detecting sensor-triggered advertising jump behaviors in applications. Please analyze the code carefully and provide accurate judgment.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            temperature=0.1,  # Reduce randomness, improve result stability
            max_tokens=120000
        )
        
        return response.choices[0].message.content
    
    def _parse_llm_response(self, response: str) -> Optional[Dict[str, Any]]:
        """Parse LLM response"""
        
        try:
            # Clean response content
            response = response.strip()
            
            # Find JSON content
            start_idx = response.find('{')
            end_idx = response.rfind('}')
            
            if start_idx != -1 and end_idx != -1:
                json_content = response[start_idx:end_idx + 1]
                result = json.loads(json_content)
                
                # Verify necessary fields
                if "trigger_condition_description" in result:
                    return result
                else:
                    log.warning("LLM response missing necessary fields")
                    return None
            else:
                log.warning("LLM response not found JSON format content")
                return None
                
        except json.JSONDecodeError as e:
            log.error(f"JSON parsing failed: {e}")
            log.debug(f"Original response: {response}")
            return None
        except Exception as e:
            log.error(f"Response parsing failed: {e}")
            return None
    
    def _get_default_result(self) -> Dict[str, Any]:
        """Get default analysis result"""
        return {
            "variable_form": None,
            "time_interval_requirement": None,
            "trigger_count_threshold": None,
            "direction_requirement": None,
            "specific_threshold_value": None,
            "trigger_condition_description": "Analysis failed"
        }
    
    def batch_analyze(self, analysis_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch analyze tasks"""
        
        log.info(f"Starting batch LLM analysis, total {len(analysis_tasks)} tasks")
        
        results = []
        for idx, task in enumerate(analysis_tasks, 1):
            log.info(f"Analyze task {idx}/{len(analysis_tasks)}")
            
            result = self.analyze_shake_pattern(
                task.get("code_snippet", ""),
                task.get("thresholds", {}),
                task.get("external_params", {}),
                task.get("dynamic_sources", []),
                task.get("call_graph", nx.DiGraph()),
                task.get("param_origin", {}),
                task.get("field_tracking"),
                task.get("shake_methods"),
                task.get("threshold_propagation")
            )
            
            # Add task information to result (avoid duplicating file field)
            result.update({
                "task_index": idx
                # Removed file_path to avoid duplication with existing "file" field
            })
            
            results.append(result)
        
        log.info("Batch LLM analysis completed")
        return results



