#!/bash/bin/bash
# Master orchestration script for unstable website experiment

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================================"
echo "UNSTABLE WEBSITE EXPERIMENT - FULL PIPELINE"
echo "========================================================================"
echo ""
echo "This experiment demonstrates why data quality is critical:"
echo "  High training accuracy ≠ Good real-time performance"
echo ""
echo "Timeline: ~60-90 minutes (depends on website responsiveness)"
echo ""
echo "========================================================================"

# Step 1: Collect data
echo ""
echo "[STEP 1/3] Collecting traffic from unstable websites (30-40 min)..."
echo "========================================================================"
python3 collect_unstable_websites.py

if [ $? -ne 0 ]; then
    echo "ERROR: Data collection failed!"
    exit 1
fi

echo ""
echo "✓ Data collection complete"

# Step 2: Train model
echo ""
echo "[STEP 2/3] Training model on unstable data (2-5 min)..."
echo "========================================================================"
python3 train_unstable_model.py

if [ $? -ne 0 ]; then
    echo "ERROR: Model training failed!"
    exit 1
fi

echo ""
echo "✓ Model training complete"

# Step 3: Analyze quality
echo ""
echo "[STEP 3/3] Analyzing data quality (5 min)..."
echo "========================================================================"
python3 analyze_unstable_quality.py

if [ $? -ne 0 ]; then
    echo "ERROR: Quality analysis failed!"
    exit 1
fi

echo ""
echo "✓ Quality analysis complete"

# Summary
echo ""
echo "========================================================================"
echo "EXPERIMENT COMPLETE ✓"
echo "========================================================================"
echo ""
echo "Results saved to:"
echo "  - Models: unstable_case/models/"
echo "  - Analysis: unstable_case/logs/"
echo ""
echo "Next steps:"
echo "  1. Review JSON results in unstable_case/logs/"
echo "  2. Test GUI with unstable model:"
echo "     python3 ../gui_capture_app.py --model unstable_case/models/unstable_model.joblib"
echo "  3. Compare with stable model:"
echo "     python3 ../gui_capture_app.py --model ../rf_model.joblib"
echo ""
echo "See README.md for detailed interpretation of results"
echo ""
