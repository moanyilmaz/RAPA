"""
Result Filter Module
Filter and process analysis results
"""
import json
from typing import List, Dict, Any, Optional
from openai import OpenAI

from src.utils.logger import log
from config.settings import DASHSCOPE_API_KEY, DASHSCOPE_BASE_URL, MODEL_NAME, MAX_RETRY_ATTEMPTS


class ResultFilter:
    """Result Filter"""
    
    def __init__(self):
        self.client = OpenAI(
            api_key=DASHSCOPE_API_KEY,
            base_url=DASHSCOPE_BASE_URL,
        )
    
    # Helper: get first non-empty value by possible keys
    def _get_first(self, data: Dict[str, Any], keys: List[str]) -> Optional[Any]:
        for k in keys:
            if k in data and data[k] not in (None, "", "null"):
                return data[k]
        return None
    
    def filter_valid_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter valid analysis results
        
        Args:
            results: Original analysis result list
            
        Returns:
            List[Dict[str, Any]]: Filtered valid results
        """
        log.info(f"Starting to filter analysis results, original count: {len(results)}")
        
        # Basic filtering
        basic_filtered = self._basic_filter(results)
        log.info(f"Results after basic filtering: {len(basic_filtered)}")
        
        if not basic_filtered:
            log.warning("No valid results after basic filtering")
            return []
        
        # LLM intelligent filtering
        llm_filtered = self._llm_intelligent_filter(basic_filtered)
        log.info(f"Results after LLM filtering: {len(llm_filtered)}")
        
        return llm_filtered
    
    def _basic_filter(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Basic filtering rules"""
        
        valid_results = []
        
        for result in results:
            analysis = result.get("analysis", {})
            # Normalize field access (support legacy Chinese keys)
            trigger_desc = self._get_first(analysis, ["trigger_condition_description", "触发条件描述"]) or ""
            variable_form = self._get_first(analysis, ["variable_form", "变量形式"]) or ""
            threshold_value_raw = self._get_first(analysis, ["specific_threshold_value", "阈值的具体数值"]) or ""
            
            # 1) Description must be valid
            if not self._is_valid_trigger_description(str(trigger_desc)):
                log.debug(f"Failed basic filtering (desc): {result.get('file', 'unknown')} - {trigger_desc}")
                continue
            
            # 2) Must be acceleration-related
            vf_lower = str(variable_form).lower()
            if not ("acceleration" in vf_lower or "加速度" in variable_form):
                log.debug(f"Failed basic filtering (variable_form not acceleration): {result.get('file', 'unknown')} - {variable_form}")
                continue
            
            # 3) Must have a clear numeric threshold
            # Try to parse a float from threshold_value
            thr_str = str(threshold_value_raw).strip()
            try:
                thr_val = float(thr_str)
            except Exception:
                # Some models return like ">=10.0" or include units; try to extract first number
                import re
                m = re.search(r"[-+]?[0-9]*\.?[0-9]+", thr_str)
                if m:
                    try:
                        thr_val = float(m.group(0))
                    except Exception:
                        thr_val = None
                else:
                    thr_val = None
            if thr_val is None:
                log.debug(f"Failed basic filtering (no numeric threshold): {result.get('file', 'unknown')} - {threshold_value_raw}")
                continue
            
            # 4) Threshold plausibility check for acceleration magnitude (m/s^2)
            # Typical human shake thresholds are around 5~20 m/s^2; we accept 0.1~50 to be tolerant
            if not (0.1 <= thr_val <= 50.0):
                log.debug(f"Failed basic filtering (implausible acceleration threshold {thr_val}): {result.get('file', 'unknown')}")
                continue
            
            valid_results.append(result)
            log.debug(f"Passed basic filtering: {result.get('file', 'unknown')}")
        
        return valid_results
    
    def _is_valid_trigger_description(self, description: str) -> bool:
        """Judge whether trigger condition description is valid"""
        
        if not description or not isinstance(description, str):
            return False
        
        # Invalid description keywords
        invalid_keywords = [
            "no explicit rule", "no clear rules", "no clear trigger conditions", "no clear", 
            "not found", "cannot determine", "analysis failed", "parsing failed", 
            "does not exist", "invalid", "error",
            # Legacy Chinese keywords for backward compatibility
            "无明确规则", "无明确触发条件", "无明确", "未找到", "无法确定",
            "分析失败", "解析失败", "不存在", "无效", "错误"
        ]
        
        description_lower = description.lower()
        
        # Check if contains invalid keywords
        for keyword in invalid_keywords:
            if keyword.lower() in description_lower:
                return False
        
        # Check if contains valid sensor-related content
        valid_keywords = [
            "sensor", "acceleration", "threshold", "shake", "trigger", "ad", 
            "jump", "detect", "exceed", "reach",
            # Legacy Chinese keywords for backward compatibility
            "传感器", "加速度", "阈值", "摇一摇", "摇动", "触发", 
            "广告", "跳转", "检测", "超过", "达到", "合加速度"
        ]
        
        has_valid_content = any(keyword.lower() in description_lower 
                              for keyword in valid_keywords)
        
        return has_valid_content and len(description.strip()) > 10
    
    def _llm_intelligent_filter(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Use LLM for intelligent filtering"""
        
        if not results:
            return []
        
        # Build filtering prompt
        results_json = json.dumps(results, ensure_ascii=False, indent=2)
        
        prompt = f"""
Please analyze the following Android application sensor analysis results and filter out truly valid shake-to-ad trigger rules.

## Filtering Requirements:
1. Remove results where "trigger_condition_description" is "No explicit rule" or similar statements
2. Remove results with undetermined or unclear thresholds
3. Keep results that clearly contain sensor threshold judgment logic
4. Keep results with specific numeric thresholds

## Original Results:
{results_json}

## Output Requirements:
Please directly output the filtered JSON array without any explanation or description.
If there are no valid results, output an empty array [].

Output Format: Strict JSON array format, starting with [ and ending with ].
"""
        
        for attempt in range(MAX_RETRY_ATTEMPTS):
            try:
                response = self._call_llm_filter(prompt)
                filtered_results = self._parse_filter_response(response)
                
                if filtered_results is not None:
                    log.success(f"LLM filtering successful, retained {len(filtered_results)} results")
                    return filtered_results
                else:
                    log.warning(f"LLM filtering result parsing failed, attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}")
                    
            except Exception as e:
                log.error(f"LLM filtering failed, attempt {attempt + 1}/{MAX_RETRY_ATTEMPTS}: {e}")
        
        log.warning("LLM filtering failed, returning basic filtering results")
        return results
    
    def _call_llm_filter(self, prompt: str) -> str:
        """Call LLM for filtering"""
        
        response = self.client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {
                    'role': 'system',
                    'content': 'You are a professional data analyst skilled at filtering and screening valid analysis results. Please strictly follow the requirements for filtering.'
                },
                {
                    'role': 'user',
                    'content': prompt
                }
            ],
            temperature=0.1,
            max_tokens=40000
        )
        
        return response.choices[0].message.content
    
    def _parse_filter_response(self, response: str) -> Optional[List[Dict[str, Any]]]:
        """Parse LLM filtering response"""
        
        try:
            response = response.strip()
            
            # Find JSON array
            start_idx = response.find('[')
            end_idx = response.rfind(']')
            
            if start_idx != -1 and end_idx != -1:
                json_content = response[start_idx:end_idx + 1]
                result = json.loads(json_content)
                
                if isinstance(result, list):
                    return result
                else:
                    log.warning("LLM response is not a list format")
                    return None
            else:
                log.warning("LLM response not found JSON array")
                return None
                
        except json.JSONDecodeError as e:
            log.error(f"JSON parsing failed: {e}")
            log.debug(f"Original response: {response}")
            return None
        except Exception as e:
            log.error(f"Response parsing failed: {e}")
            return None
    
    def flatten_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Flatten analysis results"""
        
        flattened = []
        
        for item in results:
            flat_item = {
                "index": item.get("index"),
                "file": item.get("file"),
            }
            
            # Flatten analysis field
            analysis = item.get("analysis", {})
            for key, value in analysis.items():
                if key not in flat_item:
                    flat_item[key] = value
            
            flattened.append(flat_item)
        
        log.debug(f"Flattening completed: {len(flattened)} items")
        return flattened
    
    def generate_summary_report(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate summary report"""
        
        if not results:
            return {
                "total_count": 0,
                "valid_count": 0,
                "summary": "No valid shake-to-ad trigger rules found"
            }
        
        # Statistics
        total_count = len(results)
        # Count valid by accepting either new or legacy key names and excluding invalid rules
        def _get_desc(r: Dict[str, Any]) -> str:
            return str(r.get("trigger_condition_description") or r.get("触发条件描述") or "")
        valid_count = sum(1 for r in results 
                         if _get_desc(r) and 
                         "no explicit rule" not in _get_desc(r).lower() and
                         "无明确规则" not in _get_desc(r))
        
        # Extract threshold information
        thresholds = []
        for result in results:
            threshold_value = result.get("specific_threshold_value") or result.get("阈值的具体数值")
            if threshold_value and threshold_value != "null":
                thresholds.append(str(threshold_value))
        
        # Extract variable form
        variable_forms = []
        for result in results:
            var_form = result.get("variable_form") or result.get("变量形式")
            if var_form and var_form != "null":
                variable_forms.append(str(var_form))
        
        summary = {
            "total_count": total_count,
            "valid_count": valid_count,
            "detection_rate": f"{(valid_count/total_count*100):.1f}%" if total_count > 0 else "0%",
            "common_thresholds": list(set(thresholds)),
            "common_variable_forms": list(set(variable_forms)),
            "files_analyzed": [r.get("file", "unknown") for r in results],
            "summary": f"Detected {valid_count} valid shake-to-ad trigger rules" if valid_count > 0 
                      else "No explicit shake-to-ad trigger rules found"
        }
        
        return summary



