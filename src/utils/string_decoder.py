"""
String Decoding Module
Handle encrypted/obfuscated string constants in obfuscated code
"""
import re
import base64
import hashlib
from typing import List, Dict, Any, Optional
from pathlib import Path

from src.utils.logger import log


class StringDecoder:
    """Decode obfuscated string constants"""
    
    def __init__(self):
        # Load configuration
        try:
            from config.settings import (
                ENABLE_BASE64_DECODING, ENABLE_HEX_DECODING, 
                ENABLE_XOR_DECODING, ENABLE_STRING_CONCATENATION
            )
            self.enable_base64 = ENABLE_BASE64_DECODING
            self.enable_hex = ENABLE_HEX_DECODING
            self.enable_xor = ENABLE_XOR_DECODING
            self.enable_concat = ENABLE_STRING_CONCATENATION
        except ImportError:
            # Use default values if config is not available
            self.enable_base64 = True
            self.enable_hex = True
            self.enable_xor = True
            self.enable_concat = True
        # Common string obfuscation patterns
        self.string_patterns = {
            # Base64 encoded strings
            'base64': r'([A-Za-z0-9+/]{4,}={0,2})',
            
            # Hex encoded strings
            'hex': r'([0-9a-fA-F]{2,})',
            
            # XOR encoded strings
            'xor': r'([0-9a-fA-F]{2,})\s*\^\s*([0-9a-fA-F]{2,})',
            
            # String concatenation
            'concat': r'["\'][^"\']*["\']\s*\+\s*["\'][^"\']*["\']',
            
            # Character array construction
            'char_array': r'new\s+char\s*\[\s*\d+\s*\]\s*\{[^}]*\}',
            
            # String.valueOf() calls
            'value_of': r'String\.valueOf\s*\([^)]+\)',
            
            # new String() calls
            'new_string': r'new\s+String\s*\([^)]+\)',
        }
        
        # Common sensor-related strings that might be obfuscated
        self.sensor_strings = {
            'sensor_types': [
                'TYPE_ACCELEROMETER',
                'TYPE_GRAVITY', 
                'TYPE_LINEAR_ACCELERATION',
                'TYPE_GYROSCOPE',
                'TYPE_ROTATION_VECTOR'
            ],
            'sensor_methods': [
                'registerListener',
                'unregisterListener',
                'onSensorChanged',
                'onAccuracyChanged'
            ],
            'sensor_classes': [
                'SensorManager',
                'SensorEvent',
                'Sensor'
            ]
        }
    
    def decode_strings_in_content(self, content: str) -> Dict[str, Any]:
        """Decode all obfuscated strings in content"""
        decoded_strings = {
            'base64_decoded': [],
            'hex_decoded': [],
            'xor_decoded': [],
            'concatenated': [],
            'potential_sensor_strings': []
        }
        
        # Decode Base64 strings (if enabled)
        if self.enable_base64:
            base64_matches = re.findall(self.string_patterns['base64'], content)
            for match in base64_matches:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    decoded_strings['base64_decoded'].append({
                        'original': match,
                        'decoded': decoded,
                        'is_sensor_related': self._is_sensor_related(decoded)
                    })
                except Exception as e:
                    log.debug(f"Failed to decode base64 string: {match}, error: {e}")
        
        # Decode hex strings (if enabled)
        if self.enable_hex:
            hex_matches = re.findall(self.string_patterns['hex'], content)
            for match in hex_matches:
                if len(match) % 2 == 0:  # Valid hex string
                    try:
                        decoded = bytes.fromhex(match).decode('utf-8', errors='ignore')
                        decoded_strings['hex_decoded'].append({
                            'original': match,
                            'decoded': decoded,
                            'is_sensor_related': self._is_sensor_related(decoded)
                        })
                    except Exception as e:
                        log.debug(f"Failed to decode hex string: {match}, error: {e}")
        
        # Handle XOR encoded strings (if enabled)
        if self.enable_xor:
            xor_matches = re.findall(self.string_patterns['xor'], content)
            for str1, str2 in xor_matches:
                try:
                    # Simple XOR decoding (assuming single byte key)
                    bytes1 = bytes.fromhex(str1)
                    bytes2 = bytes.fromhex(str2)
                    decoded = bytes(a ^ b for a, b in zip(bytes1, bytes2)).decode('utf-8', errors='ignore')
                    decoded_strings['xor_decoded'].append({
                        'original': f"{str1} ^ {str2}",
                        'decoded': decoded,
                        'is_sensor_related': self._is_sensor_related(decoded)
                    })
                except Exception as e:
                    log.debug(f"Failed to decode XOR string: {str1} ^ {str2}, error: {e}")
        
        # Handle string concatenation (if enabled)
        if self.enable_concat:
            concat_matches = re.findall(self.string_patterns['concat'], content)
            for match in concat_matches:
                try:
                    # Extract individual string parts
                    parts = re.findall(r'["\']([^"\']*)["\']', match)
                    concatenated = ''.join(parts)
                    decoded_strings['concatenated'].append({
                        'original': match,
                        'decoded': concatenated,
                        'is_sensor_related': self._is_sensor_related(concatenated)
                    })
                except Exception as e:
                    log.debug(f"Failed to decode concatenated string: {match}, error: {e}")
        
        # Check for potential sensor-related strings
        for category, strings in self.sensor_strings.items():
            for string in strings:
                if string.lower() in content.lower():
                    decoded_strings['potential_sensor_strings'].append({
                        'category': category,
                        'string': string,
                        'context': self._extract_context(content, string)
                    })
        
        return decoded_strings
    
    def _is_sensor_related(self, string: str) -> bool:
        """Check if a decoded string is sensor-related"""
        string_lower = string.lower()
        
        # Check against sensor-related keywords
        sensor_keywords = [
            'sensor', 'accelerometer', 'gyroscope', 'gravity',
            'register', 'listener', 'event', 'manager',
            'threshold', 'shake', 'motion', 'gesture'
        ]
        
        return any(keyword in string_lower for keyword in sensor_keywords)
    
    def _extract_context(self, content: str, target_string: str, context_size: int = 100) -> str:
        """Extract context around a target string"""
        try:
            index = content.lower().find(target_string.lower())
            if index != -1:
                start = max(0, index - context_size)
                end = min(len(content), index + len(target_string) + context_size)
                return content[start:end]
        except Exception as e:
            log.debug(f"Failed to extract context for {target_string}: {e}")
        
        return ""


class StringReplacer:
    """Replace obfuscated strings with decoded versions"""
    
    def __init__(self):
        self.decoder = StringDecoder()
    
    def replace_obfuscated_strings(self, content: str) -> str:
        """Replace obfuscated strings with their decoded versions"""
        modified_content = content
        
        # Decode all strings first
        decoded_strings = self.decoder.decode_strings_in_content(content)
        
        # Replace Base64 strings
        for item in decoded_strings['base64_decoded']:
            if item['is_sensor_related']:
                # Replace with decoded version
                modified_content = modified_content.replace(
                    f'"{item["original"]}"', 
                    f'"{item["decoded"]}"'
                )
        
        # Replace hex strings
        for item in decoded_strings['hex_decoded']:
            if item['is_sensor_related']:
                modified_content = modified_content.replace(
                    f'"{item["original"]}"', 
                    f'"{item["decoded"]}"'
                )
        
        # Replace concatenated strings
        for item in decoded_strings['concatenated']:
            if item['is_sensor_related']:
                modified_content = modified_content.replace(
                    item['original'], 
                    f'"{item["decoded"]}"'
                )
        
        return modified_content


class StringAnalyzer:
    """Analyze string usage patterns for sensor detection"""
    
    def __init__(self):
        self.decoder = StringDecoder()
    
    def analyze_string_patterns(self, content: str) -> Dict[str, Any]:
        """Analyze string patterns for sensor-related indicators"""
        analysis = {
            'obfuscated_strings': 0,
            'decoded_strings': 0,
            'sensor_related_strings': 0,
            'string_obfuscation_level': 0,
            'potential_sensor_constants': []
        }
        
        # Decode strings
        decoded_strings = self.decoder.decode_strings_in_content(content)
        
        # Count obfuscated strings
        analysis['obfuscated_strings'] = (
            len(decoded_strings['base64_decoded']) +
            len(decoded_strings['hex_decoded']) +
            len(decoded_strings['xor_decoded']) +
            len(decoded_strings['concatenated'])
        )
        
        # Count decoded strings
        analysis['decoded_strings'] = sum(
            len(items) for items in decoded_strings.values()
            if isinstance(items, list)
        )
        
        # Count sensor-related strings
        sensor_related = []
        for category, items in decoded_strings.items():
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict) and item.get('is_sensor_related', False):
                        sensor_related.append(item)
        
        analysis['sensor_related_strings'] = len(sensor_related)
        analysis['potential_sensor_constants'] = sensor_related
        
        # Calculate obfuscation level
        total_strings = analysis['obfuscated_strings'] + analysis['decoded_strings']
        if total_strings > 0:
            analysis['string_obfuscation_level'] = analysis['obfuscated_strings'] / total_strings
        
        return analysis 