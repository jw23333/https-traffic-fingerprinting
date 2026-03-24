# Unstable Website Experiment

## Overview

This experiment demonstrates a critical insight: **High offline training accuracy does not guarantee good real-time GUI performance when the traffic data is unstable.**

### The Problem

During deployment testing on live websites (apple.com, microsoft.com, amazon.com, nytimes.com), our model achieved high test accuracy (~98%) but made random predictions through the GUI in real-time. This seemed paradoxical: how can a model be accurate in testing but fail in deployment?

### The Answer: Data Quality

These websites have **highly variable traffic patterns** across visits due to:
- Dynamic content loading (JavaScript, animations)
- Adaptive page rendering
- Server-side content personalization
- Network-dependent resource fetching
- CDN-based load balancing

This variability means that burst-pair features extracted from one visit look completely different from the next visit of the *same* website. The model **learns the noise, not the signal**.

## Experiment Structure

```
experiments/
├── unstable_case/
│   ├── raw/              # Raw pcap files from unstable sites
│   ├── pairs/            # Converted burst-pair CSV files
│   ├── models/           # Trained model bundles
│   └── logs/             # Analysis results JSON
├── collect_unstable_websites.py    # Step 1: Data collection
├── train_unstable_model.py         # Step 2: Train model
├── analyze_unstable_quality.py     # Step 3: Quality analysis
├── run_all.sh                      # Master orchestration script
└── README.md             # This file
```

## How to Run

### Option A: Run Full Pipeline (Recommended)

```bash
cd /path/to/experiments
bash run_all.sh
```

This will:
1. Collect traffic from 4 unstable websites (50 visits each = 200 captures)
2. Convert pcap files to burst-pair CSVs
3. Train a model on unstable data
4. Analyze data quality with variance metrics
5. Display findings

**Time estimate: ~60-90 minutes** (depends on website responsiveness)

### Option B: Run Steps Individually

```bash
# Step 1: Collect data (30-40 min)
python3 collect_unstable_websites.py

# Step 2: Train model (2-5 min)
python3 train_unstable_model.py

# Step 3: Analyze quality (5 min)
python3 analyze_unstable_quality.py
```

### Option C: Quick Demo (No Data Collection)

If you already have unstable data collected:

```bash
python3 train_unstable_model.py
python3 analyze_unstable_quality.py
```

## Expected Results

### Model Performance Metrics

```
Training Accuracy: ~97-99%
Test Accuracy:     ~95-97%
```

**Looks good!** But then try using it in the GUI...

### Data Quality Results

| Metric | Result | Interpretation |
|--------|--------|-----------------|
| Variance Ratio | 5-15x | HIGH - Traffic highly unstable |
| Avg Feature CV | 40-60% | HIGH - Features inconsistent |
| Inter-site Overlap | >0.70 | HIGH - Model confused |

### What This Means

- **Variance Ratio > 5**: Unstable websites produce 5-15x different numbers of burst-pairs across visits
- **CV > 40%**: Feature values swing wildly; the model can't learn stable patterns
- **Overlap > 0.70**: Different website features look similar; classification becomes random

## GUI Testing: Real-Time Performance

After training, test the unstable model with the GUI:

```bash
# From main code directory
python3 gui_capture_app.py --model experiments/unstable_case/models/unstable_model.joblib
```

**What you'll observe:**
- Predictions are mostly "No monitored site detected"
- Or, when predictions appear, they change drastically between visits
- Confidence scores are low (< 0.50)
- Feature importance explanations are contradictory (different features top-ranked each time)

This is **not** a bug—it's evidence that the model learned unstable, noisy patterns.

## Comparison: Stable vs. Unstable

To see the full contrast, train both models and run them:

```bash
# Unstable model (from this experiment)
python3 gui_capture_app.py --model experiments/unstable_case/models/unstable_model.joblib

# Original stable model (trained on NHS pages)
python3 gui_capture_app.py --model rf_model.joblib
```

**Observations:**
- The stable model makes consistent, high-confidence predictions
- The unstable model flails, producing random outputs
- Feature importance is interpretable for stable model, contradictory for unstable

## Deep Dive: What the Metrics Show

### Variance Ratio

The variance ratio measures how many more burst-pairs are captured on the "busiest" visit vs. the "quietest" visit for a given website:

```
Variance Ratio = max(pairs_per_visit) / min(pairs_per_visit)
```

- Ratio < 3.0: EXCELLENT (stable, predictable)
- Ratio 3-5: GOOD
- Ratio 5-10: OK (borderline)
- Ratio > 10: HIGH (unstable, unreliable)

**Why this matters:** If the number of burst-pairs varies 10x, it means the traffic itself is fundamentally different across visits. Features extracted from 50 pairs will be different from features from 500 pairs. The model can't learn a stable mapping.

### Coefficient of Variation (CV)

For each feature, we compute:

```
CV = (std_dev / mean) × 100%
```

A feature with CV > 50% is essentially noise—its value swings from < mean to > mean unpredictably.

### Inter-site Feature Overlap

We measure the feature-space distance between different websites:

```
Overlap = 1.0 - (euclidean_distance / max_norm)
```

- Overlap > 0.80: Features almost identical; sites indistinguishable
- Overlap 0.70-0.80: High overlap; frequent misclassification
- Overlap < 0.50: Good separation; model can discriminate

## Implications for Implementation

This experiment validates three key design decisions in the final system:

1. **Site Curation**: We removed apple.com, microsoft.com, and other high-variance sites
   - Final dataset uses only stable sites (NHS pages)
   - Variance ratio < 3.0 across all final sites

2. **Conservative Decision Rules**: We added three gates
   - `confidence >= 0.50` (reject low-confidence predictions)
   - `margin >= 0.20` (require clear separation between top-2 classes)
   - `label in {chickenpox, measles}` (reject non-monitored predictions)
   - These gates filter out the high-entropy decisions caused by unstable data

3. **Importance of Data Quality**: Data quality is prerequisite, not afterthought
   - `check_data_quality.py` is used *before* training
   - Sites with variance > 5.0 are removed
   - Remaining sites form the actual training set

## Files and Outputs

### Raw Captures
```
unstable_case/raw/{site}/{site}_{visit}.pcap
```
Original HTTPS traffic captures (2.5s each, port 443 only)

### Processed Burst Pairs
```
unstable_case/pairs/{site}/{site}_{visit}_pairs.csv
```
Columns: out_bytes, in_bytes, out_pkts, in_pkts, out_start, out_end, in_start, in_end

### Model Bundle
```
unstable_case/models/unstable_model.joblib
```
Dictionary containing:
- `"model"`: Trained RandomForest (200 trees)
- `"label_encoder"`: LabelEncoder for site names
- `"feature_names"`: List of 40 feature names (for schema alignment)

### Analysis Logs
```
unstable_case/logs/training_results.json          # Training metrics
unstable_case/logs/quality_analysis.json          # Variance/CV/overlap
```

## TL;DR

**Problem:** Model is 97% accurate in testing but randomly guesses in GUI.

**Root Cause:** Training data from unstable websites (high variance in traffic patterns).

**Evidence:** Variance ratio > 5x, Feature CV > 50%, Inter-site overlap > 0.70.

**Solution:** Use only stable websites (variance < 3x) for training; implement conservative decision gates.

**Lesson:** Machine learning success depends on data quality. Offline metrics are necessary but not sufficient.
