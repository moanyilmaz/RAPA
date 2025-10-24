"""
SSAR Analysis Project Main Entry
Integrates APK decompilation and shake-to-ad detection functionality
"""
import os
import sys
import argparse
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.utils.logger import log
from src.utils.apk_reverser import ApkReverser
from src.ssar_analyzer import analyze_apk


def setup_arguments():
    """Setup command line arguments"""
    parser = argparse.ArgumentParser(
        description="Android Shake-to-Ad Detection Tool (Shake Sensor Ad Redirect Analyzer)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage Examples:
               python main.py --apk hupu.apk                    # Analyze specific APK
             python main.py --batch                          # Batch analyze all APKs
             python main.py --reverse                        # Execute APK decompilation only
             python main.py --apk test.apk --reverse --analyze  # Decompile then analyze
        """
    )
    
    parser.add_argument(
        '--apk', '-a',
        type=str,
        help='Specify APK filename to analyze'
    )
    
    parser.add_argument(
        '--batch', '-b',
        action='store_true',
        help='Batch analyze all APK files in apk directory'
    )
    
    parser.add_argument(
        '--reverse', '-r',
        action='store_true',
        help='Execute APK decompilation (using JADX)'
    )
    
    parser.add_argument(
        '--analyze', '-A',
        action='store_true',
        help='Execute shake-to-ad analysis'
    )
    
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='List all APK files in apk directory'
    )
    
    parser.add_argument(
        '--config', '-c',
        type=str,
        help='Specify configuration file path'
    )
    
    return parser


def list_available_apks():
    """List available APK files"""
    apk_dir = Path("./apk")
    
    if not apk_dir.exists():
        log.warning("APK directory does not exist")
        return []
    
    apk_files = []
    for item in apk_dir.iterdir():
        # Check for APK folders (decompiled APK directories)
        if item.is_dir() and '.apk' in item.name:
            apk_files.append(item.name)
        # Check for actual APK files
        elif item.is_file() and item.suffix == '.apk':
            apk_files.append(item.name)
    
    if apk_files:
        log.info("Available APK files:")
        for i, apk in enumerate(apk_files, 1):
            log.info(f"  {i}. {apk}")
    else:
        log.info("No APK files found")
    
    return apk_files


def run_apk_reverse():
    """Run APK decompilation"""
    log.info("Starting APK decompilation process")
    
    try:
        reverser = ApkReverser()
        reverser.run()
        log.success("APK decompilation completed")
        return True
    except Exception as e:
        log.error(f"APK decompilation failed: {e}")
        return False


def check_apk_decompiled(apk_name: str) -> bool:
    """Check if APK is already decompiled in apk directory"""
    apk_dir = Path("./apk")
    decompiled_path = apk_dir / apk_name
    
    if decompiled_path.exists() and decompiled_path.is_dir():
        log.info(f"Found existing decompiled APK: {apk_name}")
        return True
    return False


def decompile_single_apk(apk_name: str) -> bool:
    """Decompile single APK from raw_apks directory"""
    from config.settings import APK_SOURCE_DIR, APK_OUTPUT_DIR, JADX_PATH, THREAD_COUNT
    
    raw_apk_path = Path(APK_SOURCE_DIR) / apk_name
    if not raw_apk_path.exists():
        log.error(f"APK file not found in raw_apks: {apk_name}")
        return False
    
    output_path = Path(APK_OUTPUT_DIR) / apk_name
    
    command = [
        JADX_PATH,
        "-d", str(output_path),
        "-j", str(THREAD_COUNT),
        str(raw_apk_path)
    ]
    
    try:
        log.info(f"Starting decompilation: {apk_name}")
        import subprocess
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            log.success(f"Decompilation successful: {apk_name}")
            return True
        else:
            log.error(f"Decompilation failed: {apk_name}, error: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        log.error(f"Decompilation timeout: {apk_name}")
        return False
    except Exception as e:
        log.error(f"Decompilation error: {apk_name}, error: {e}")
        return False


def run_single_analysis(apk_name: str):
    """Run single APK analysis"""
    # Setup APK-specific logger
    from src.utils.logger import setup_apk_logger
    setup_apk_logger(apk_name)
    
    log.info(f"Starting single APK analysis: {apk_name}")
    log.info(f"APK-specific log file: logs/{apk_name}_analysis.log")
    
    # Check if APK is already decompiled
    if not check_apk_decompiled(apk_name):
        log.info(f"APK {apk_name} not found in apk directory, checking raw_apks...")
        
        # Check if APK exists in raw_apks
        raw_apk_path = Path("./raw_apks") / apk_name
        if raw_apk_path.exists():
            log.info(f"Found APK in raw_apks, starting decompilation...")
            if not decompile_single_apk(apk_name):
                log.error(f"Failed to decompile {apk_name}")
                return False
        else:
            log.error(f"APK {apk_name} not found in either apk or raw_apks directory")
            return False
    
    # Set environment variable
    os.environ["APK_NAME"] = apk_name
    
    try:
        report = analyze_apk(apk_name)
        
        # Display result summary
        log.info("="*60)
        log.info("Analysis Result Summary")
        log.info("="*60)
        log.info(f"APK Name: {report.get('apk_name', 'Unknown')}")
        log.info(f"Analysis Time: {report.get('analysis_time', 'Unknown')}")
        log.info(f"Found Results: {report.get('total_count', 0)}")
        log.info(f"Valid Results: {report.get('valid_count', 0)}")
        log.info(f"Detection Rate: {report.get('detection_rate', '0%')}")
        log.info(f"Conclusion: {report.get('summary', 'Unknown')}")
        
        if report.get('common_thresholds'):
            log.info(f"Common Thresholds: {report['common_thresholds']}")
        
        if report.get('output_files'):
            log.info("Output Files:")
            for key, path in report['output_files'].items():
                log.info(f"  {key}: {path}")
        
        log.info("="*60)
        
        return True
        
    except Exception as e:
        log.error(f"Analysis failed: {e}")
        return False


def find_raw_apks() -> list:
    """Find all APK files in raw_apks directory"""
    raw_apks_dir = Path("./raw_apks")
    
    if not raw_apks_dir.exists():
        log.warning("raw_apks directory does not exist")
        return []
    
    apk_files = []
    for item in raw_apks_dir.iterdir():
        if item.is_file() and item.suffix == '.apk':
            apk_files.append(item.name)
    
    if apk_files:
        log.info(f"Found {len(apk_files)} APK files in raw_apks:")
        for i, apk in enumerate(apk_files, 1):
            log.info(f"  {i}. {apk}")
    else:
        log.info("No APK files found in raw_apks")
    
    return apk_files


def decompile_all_raw_apks() -> bool:
    """Decompile all APK files in raw_apks directory"""
    raw_apks = find_raw_apks()
    
    if not raw_apks:
        log.warning("No APK files found in raw_apks for decompilation")
        return False
    
    log.info("Starting batch decompilation of all APK files in raw_apks...")
    
    success_count = 0
    skip_count = 0
    total_count = len(raw_apks)
    
    for i, apk_name in enumerate(raw_apks, 1):
        log.info(f"Decompilation progress: {i}/{total_count} - {apk_name}")
        
        # Check if APK is already decompiled
        if check_apk_decompiled(apk_name):
            log.info(f"Skipping {apk_name} - already decompiled")
            skip_count += 1
            success_count += 1  # Count as success since it's available for analysis
        else:
            if decompile_single_apk(apk_name):
                success_count += 1
        
        log.info("-" * 40)
    
    log.info(f"Batch decompilation completed: {success_count}/{total_count} successful")
    if skip_count > 0:
        log.info(f"Skipped {skip_count} APKs (already decompiled)")
    
    return success_count > 0


def run_batch_analysis():
    """Run batch analysis"""
    log.info("Starting batch analysis")
    log.info("Step 1: Decompile all APK files in raw_apks directory")
    
    # Attempt decompilation first; if none found in raw_apks, fall back to existing decompiled APKs
    decompilation_done = decompile_all_raw_apks()
    if not decompilation_done:
        log.warning("Batch decompilation skipped or no APK files found in raw_apks")
    
    log.info("Step 2: Analyze all decompiled APK files")
    log.info("Each APK will have its own log file in logs/ directory")
    
    # Collect all available APKs from apk directory (already decompiled or newly decompiled)
    apk_files = list_available_apks()
    
    if not apk_files:
        log.warning("No APK files found for analysis")
        return False
    
    success_count = 0
    total_count = len(apk_files)
    
    for i, apk_name in enumerate(apk_files, 1):
        log.info(f"Batch analysis progress: {i}/{total_count} - {apk_name}")
        
        if run_single_analysis(apk_name):
            success_count += 1
        
        log.info("-" * 40)
    
    log.info(f"Batch analysis completed: {success_count}/{total_count} successful")
    log.info("Check individual APK log files in logs/ directory for detailed analysis logs")
    return success_count > 0


def main():
    """Main function"""
    parser = setup_arguments()
    args = parser.parse_args()
    
    log.info("SSAR Analysis Tool Starting")
    log.info(f"Project Root: {project_root}")
    
    # If no arguments specified, show help
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    # List APK files
    if args.list:
        list_available_apks()
        return
    
    # APK decompilation
    if args.reverse:
        success = run_apk_reverse()
        if not success:
            return
    
    # Single APK analysis
    if args.apk:
        # If analyze parameter specified or no reverse specified, default to analysis
        if args.analyze or not args.reverse:
            run_single_analysis(args.apk)
    
    # Batch analysis
    elif args.batch:
        # If analyze parameter specified or no reverse specified, default to analysis
        if args.analyze or not args.reverse:
            run_batch_analysis()
    
    # If only analyze parameter specified but no APK
    elif args.analyze:
        log.warning("Please use --apk to specify APK filename or use --batch for batch analysis")
        parser.print_help()
    
    log.info("SSAR Analysis Tool execution completed")


if __name__ == "__main__":
    main()
