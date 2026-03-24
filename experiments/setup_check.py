#!/usr/bin/env python3
"""
Quick setup script - verifies dependencies and shows next steps.
"""

import sys
from pathlib import Path

def check_setup():
    """Verify the experiment is ready to run."""
    
    print("\n" + "="*70)
    print("UNSTABLE WEBSITE EXPERIMENT - SETUP CHECK")
    print("="*70)
    
    # Check directory structure
    experiment_dir = Path(__file__).parent / "unstable_case"
    required_dirs = ["raw", "pairs", "models", "logs"]
    
    print("\n✓ Directory structure:")
    for d in required_dirs:
        dir_path = experiment_dir / d
        status = "✓" if dir_path.exists() else "✗"
        print(f"  {status} {d}/")
    
    # Check scripts
    print("\n✓ Required scripts:")
    required_scripts = [
        "collect_unstable_websites.py",
        "train_unstable_model.py", 
        "analyze_unstable_quality.py",
        "compare_models.py",
        "run_all.sh",
    ]
    
    for script in required_scripts:
        script_path = Path(__file__).parent / script
        status = "✓" if script_path.exists() else "✗"
        print(f"  {status} {script}")
    
    # Check parent module availability
    print("\n✓ Dependencies (parent module access):")
    parent_dir = Path(__file__).parent.parent
    required_modules = [
        "collect_dataset.py",
        "process_pcap.py",
        "process_dataset_pairs.py",
        "capture_safari_all.py",
        "check_data_quality.py",
    ]
    
    for module in required_modules:
        module_path = parent_dir / module
        status = "✓" if module_path.exists() else "✗"
        print(f"  {status} {module}")
    
    # Quick start guide
    print("\n" + "-"*70)
    print("QUICK START GUIDE")
    print("-"*70)
    
    print("\n1. Full Pipeline (Recommended):")
    print("   cd /Users/yiweiwang/Desktop/Dissertation/Code/experiments")
    print("   bash run_all.sh")
    
    print("\n2. Step by Step:")
    print("   python3 collect_unstable_websites.py      # 30-40 min")
    print("   python3 train_unstable_model.py            # 2-5 min")
    print("   python3 analyze_unstable_quality.py        # 5 min")
    print("   python3 compare_models.py                  # instant")
    
    print("\n3. Test Unstable Model:")
    print("   python3 ../gui_capture_app.py --model unstable_case/models/unstable_model.joblib")
    
    print("\n4. Compare with Stable Model:")
    print("   python3 ../gui_capture_app.py --model ../rf_model.joblib")
    
    print("\n" + "="*70)
    print("Setup check complete! Ready to run experiment.")
    print("="*70 + "\n")


if __name__ == "__main__":
    check_setup()
