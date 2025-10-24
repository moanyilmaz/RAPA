# SSAR Analysis Configuration

# API Configuration
DASHSCOPE_API_KEY = "your_api_key"
DASHSCOPE_BASE_URL = "https://dashscope.aliyuncs.com/compatible-mode/v1"
MODEL_NAME = "qwen3-235b-a22b-instruct-2507"

# JADX Configuration
JADX_PATH = "your_jadx_path/jadx.bat"
APK_SOURCE_DIR = "./raw_apks/"
APK_OUTPUT_DIR = "./apk/"

# Analysis Configuration
MAX_RETRY_ATTEMPTS = 3
THREAD_COUNT = 4

# File Extensions
JAVA_EXTENSIONS = [".java"]
APK_EXTENSIONS = [".apk"]

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "./logs/ssar_analysis.log"

# Anti-obfuscation Features
ENABLE_ANTI_OBFUSCATION = True
ENABLE_STRING_DECODING = True
ENABLE_SEMANTIC_DETECTION = True
ENABLE_CONTROL_FLOW_ANALYSIS = True

# Detection Thresholds
OBFUSCATION_CONFIDENCE_THRESHOLD = 0.6
STRING_OBFUSCATION_THRESHOLD = 0.3

# String Decoding Options
ENABLE_BASE64_DECODING = True
ENABLE_HEX_DECODING = True
ENABLE_XOR_DECODING = True
ENABLE_STRING_CONCATENATION = True
