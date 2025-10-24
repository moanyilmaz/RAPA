"""
APK reverse engineering module using JADX
"""
import os
import time
import subprocess
from typing import List, Tuple
from pathlib import Path

from src.utils.logger import log
from config.settings import JADX_PATH, APK_SOURCE_DIR, APK_OUTPUT_DIR, THREAD_COUNT


class ApkReverser:
    """APK reverse engineering tool"""
    
    def __init__(self, jadx_path: str = JADX_PATH, 
                 source_dir: str = APK_SOURCE_DIR,
                 output_dir: str = APK_OUTPUT_DIR,
                 thread_count: int = THREAD_COUNT):
        self.jadx_path = jadx_path
        self.source_dir = source_dir
        self.output_dir = output_dir
        self.thread_count = thread_count
        self.apk_list: List[Tuple[str, float]] = []
        
        # Ensure output directory exists
        Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    def find_apk_files(self, directory: str) -> None:
        """Recursively find all APK files in directory"""
        log.info(f"Searching APK files in: {directory}")
        
        if os.path.isfile(directory):
            if directory.endswith(".apk"):
                mtime = os.path.getmtime(directory)
                self.apk_list.append((directory, mtime))
                log.debug(f"Found APK file: {directory}")
        else:
            try:
                for item in os.listdir(directory):
                    item_path = os.path.join(directory, item)
                    self.find_apk_files(item_path)
            except PermissionError as e:
                log.warning(f"Cannot access directory {directory}: {e}")
        
        log.info(f"APK search completed, found {len(self.apk_list)} files")
    
    def reverse_apk(self, apk_path: str) -> bool:
        """Reverse engineer single APK file"""
        apk_name = os.path.basename(apk_path)
        output_path = os.path.join(self.output_dir, apk_name)
        
        command = [
            self.jadx_path,
            "-d", output_path,
            "-j", str(self.thread_count),
            apk_path
        ]
        
        try:
            log.info(f"Starting reverse engineering: {apk_name}")
            result = subprocess.run(command, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                log.success(f"Reverse engineering successful: {apk_name}")
                return True
            else:
                log.error(f"Reverse engineering failed: {apk_name}, error: {result.stderr}")
                return False
                
        except subprocess.TimeoutExpired:
            log.error(f"Reverse engineering timeout: {apk_name}")
            return False
        except Exception as e:
            log.error(f"Reverse engineering error: {apk_name}, error: {e}")
            return False
    
    def batch_reverse(self) -> None:
        """Batch reverse engineer APK files"""
        if not self.apk_list:
            log.warning("No APK files found")
            return
        
        # Sort by modification time
        self.apk_list.sort(key=lambda x: x[1], reverse=False)
        
        total_count = len(self.apk_list)
        success_count = 0
        start_time = time.time()
        
        log.info(f"Starting batch reverse engineering, {total_count} APK files")
        
        for index, (apk_path, _) in enumerate(self.apk_list, 1):
            log.info(f"[{index}/{total_count}] Processing: {os.path.basename(apk_path)}")
            
            if self.reverse_apk(apk_path):
                success_count += 1
        
        end_time = time.time()
        duration = end_time - start_time
        
        log.info(f"Batch reverse engineering completed")
        log.info(f"Success: {success_count}/{total_count}")
        log.info(f"Total time: {duration:.2f}s")
    
    def run(self) -> None:
        """Run APK reverse engineering process"""
        log.info("Starting APK reverse engineering process")
        
        # Check if JADX tool exists
        if not os.path.exists(self.jadx_path):
            log.error(f"JADX tool not found: {self.jadx_path}")
            return
        
        # Find APK files
        self.find_apk_files(self.source_dir)
        
        # Batch reverse engineer
        self.batch_reverse()
        
        log.info("APK reverse engineering process completed")


def main():
    """Main function"""
    reverser = ApkReverser()
    reverser.run()


