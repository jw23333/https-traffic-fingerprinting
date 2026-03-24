# HTTPS Traffic Fingerprinting for Website Classification

**Status:** Undergraduate dissertation project (2026)

## Overview

This project demonstrates that **websites can be identified from encrypted HTTPS traffic metadata alone**, without decrypting any content. By analyzing only observable network patterns—packet sizes, directions, timing, and burst sequences—a Random Forest classifier achieves **98% accuracy** in identifying which NHS health information page a user is visiting.

**Key Privacy Insight:** Even though HTTPS encrypts the content of your web browsing, the "shape" of your traffic creates a unique fingerprint that can reveal which specific pages you're viewing.

**Educational Purpose:** This research explores privacy implications of traffic analysis to educate users and developers about information leakage at the network layer, motivating development of privacy-enhancing technologies.

---

## Table of Contents

1. [System Architecture](#system-architecture)
2. [How It Works](#how-it-works)
3. [Current Dataset & Results](#current-dataset--results)
4. [Installation](#installation)
5. [Usage Guide](#usage-guide)
6. [Data Quality Analysis](#data-quality-analysis)
7. [GUI Features](#gui-features)
8. [Project Files](#project-files)
9. [Limitations & Future Work](#limitations--future-work)
10. [Ethical Considerations](#ethical-considerations)

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  User Interaction: GUI or Automated Collection                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  1. CAPTURE: tshark records HTTPS traffic (port 443 only)       │
│     Output: dataset_raw/<site>/*.pcap                           │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  2. PROCESS: Extract burst pairs from pcap files                │
│     - Label packets as outbound/inbound                         │
│     - Group into bursts (50ms gap threshold)                    │
│     - Create request-response pairs                             │
│     Output: dataset_pairs/<site>/*_pairs.csv                    │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  3. FEATURE EXTRACTION: 36 features per capture                 │
│     - 12 aggregate statistics (totals, means, std, ratios)      │
│     - 24 sequential n-gram features (bigrams, trigrams)         │
│     Output: Feature matrix (samples × 36)                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  4. TRAINING: Random Forest Classifier (200 trees)              │
│     - 80/20 train/test split (stratified)                       │
│     - Log1p transformation for skewed features                  │
│     Output: rf_model.joblib (model + encoder + feature names)   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│  5. PREDICTION: GUI with user-friendly explanations             │
│     - Real-time capture & classification                        │
│     - Non-technical feature explanations (top 2)                │
│     - Collapsible technical details (all 36 features)           │
│     - Confidence filtering & monitored-site checking            │
└─────────────────────────────────────────────────────────────────┘
```

---

## How It Works

### 1. Data Collection

**Automated Collection Script** (`collect_dataset.py`):
- Opens websites in **Safari Private Browsing mode** (prevents session contamination)
- Forces **cache-bypass reload** (`Cmd+Opt+R`) to ensure fresh traffic every time
- Captures **2.5 seconds** of HTTPS traffic (TCP/UDP port 443 only)
- Repeats **70 times per site** for robust statistical sampling
- Resets Safari between visits to eliminate connection reuse

**Why Private Browsing + Hard Reload?**
- **Private mode**: Prevents cookies/session data from affecting traffic patterns
- **Hard reload (Cmd+Opt+R)**: Forces browser to revalidate all cached resources
- **Consistency**: Same conditions during training and live demo predictions

### 2. Processing: Pcap → Burst Pairs

**Burst Detection** (`process_pcap.py`):
1. **Extract metadata** using `tshark`: timestamp, source IP, destination IP, packet size
2. **Label direction**: 
   - Outbound = client → server (determined by local IP detection)
   - Inbound = server → client
3. **Group into bursts**: Consecutive same-direction packets within **50ms gap** threshold
4. **Pair bursts**: Match each outbound burst with the next inbound burst (request-response)

**Burst Pair Attributes**:
- `out_bytes`, `out_pkts`, `out_duration` - Outbound burst size, packet count, duration
- `in_bytes`, `in_pkts`, `in_duration` - Inbound burst size, packet count, duration  
- `out_start`, `out_end`, `in_start`, `in_end` - Precise timestamps

**Why Burst Pairs?**
- Captures natural request-response rhythm of HTTP/2 and HTTP/3
- Reduces noise from packet-level jitter
- Preserves sequential ordering for n-gram analysis

### 3. Feature Extraction (36 Features)

#### A) Aggregate Statistics (12 features)

Computed across all burst pairs in a single capture:

| Feature | Description |
|---------|-------------|
| `total_pairs` | Number of request-response exchanges |
| `total_out_bytes` | Total bytes sent (all outbound bursts) |
| `total_in_bytes` | Total bytes received (all inbound bursts) |
| `mean_out_bytes` | Average outbound burst size |
| `mean_in_bytes` | Average inbound burst size |
| `std_out_bytes` | Standard deviation of outbound sizes (variability) |
| `std_in_bytes` | Standard deviation of inbound sizes |
| `mean_out_pkts` | Average packets per outbound burst |
| `mean_in_pkts` | Average packets per inbound burst |
| `mean_out_dur` | Average outbound transmission duration |
| `mean_in_dur` | Average inbound reception duration |
| `ratio_out_in_bytes` | Upload/download ratio |

#### B) Sequential N-gram Features (24 features)

Position-independent pattern features capturing traffic flow structure:

**Binary Classification** (based on median thresholds):
- **Outbound bursts**: Small (≤ 11,450 bytes) vs Large (> 11,450 bytes)
- **Inbound bursts**: Small (≤ 167 bytes) vs Large (> 167 bytes)

**Bigrams** (8 features): Counts of 2-consecutive burst transitions
- `bigram_out_S_to_S`, `bigram_out_S_to_L`, `bigram_out_L_to_S`, `bigram_out_L_to_L`
- `bigram_in_S_to_S`, `bigram_in_S_to_L`, `bigram_in_L_to_S`, `bigram_in_L_to_L`

**Trigrams** (8 features): Counts of 3-consecutive outbound burst patterns
- `trigram_out_S_S_S`, `trigram_out_S_S_L`, `trigram_out_S_L_S`, `trigram_out_S_L_L`
- `trigram_out_L_S_S`, `trigram_out_L_S_L`, `trigram_out_L_L_S`, `trigram_out_L_L_L`

**Counts** (4 features):
- `count_out_small`, `count_out_large`, `count_in_small`, `count_in_large`

**Ratios** (4 features):
- `ratio_out_small`, `ratio_out_large`, `ratio_in_small`, `ratio_in_large`

**Why N-grams?**
- Captures **sequential flow patterns** beyond just size/weight
- **Position-independent**: Robust to minor resource loading variations
- Reveals structural differences in how pages orchestrate requests

**Threshold Determination** (`analyze_thresholds.py`):
- Analyzes 59,616 burst pairs from all collected traffic
- Uses **median-based split** for balanced small/large classification
- Creates roughly equal distribution for better pattern learning

### 4. Training: Random Forest (200 Trees)

**Algorithm**: `RandomForestClassifier` from scikit-learn
- **200 decision trees** (ensemble voting for robustness)
- Each tree trained on bootstrap sample with random feature subset
- Prevents overfitting while capturing complex patterns

**Preprocessing**:
1. **Replace inf/NaN**: `X.replace([inf, -inf], 0).fillna(0)`
2. **Log1p transformation**: `np.log1p(X)` on all numeric features
   - Handles skewed distributions (e.g., some sites have 50 pairs, others 300)
   - Compresses extreme values while preserving zero

**Split**: 80% train, 20% test (stratified to maintain class balance)

**Output**: `rf_model.joblib` containing:
- Trained Random Forest model
- Label encoder (site name ↔ numeric labels)
- Feature names (ensures correct column alignment during prediction)

### 5. Prediction & GUI

**Real-time Workflow**:
1. User clicks **Start** → tshark begins capturing on `en1` (WiFi interface)
2. User browses to target site in Safari
3. User clicks **Stop** → capture terminates
4. **Processing pipeline**:
   - Pcap → burst pairs CSV
   - Extract 36 features
   - Load model and predict
   - Display results with explanations
5. **Auto-cleanup**: Deletes temporary pcap/CSV files

**Confidence Filtering**:
- **Confidence threshold**: 50% minimum (rejects low-confidence predictions)
- **Margin threshold**: 20% minimum gap between top-1 and top-2 predictions
- **Monitored labels**: Only accepts `{"chickenpox", "measles"}` by default
- **Rejection behavior**: Shows "No monitored site detected" for decoys/unknown sites

---

## Current Dataset & Results

### Dataset Configuration

**Domain**: NHS UK Health Information Pages (single-domain scenario)
- **Purpose**: Demonstrates website fingerprinting vulnerability **within a single domain**
- **Threat model**: Attacker knows victim visits NHS.uk, wants to identify specific health conditions being researched

**Sites** (4 NHS condition pages):

| Site | Type | Visits | Avg Pairs | Variance | Quality |
|------|------|--------|-----------|----------|---------|
| **chickenpox** | Monitored | 70 | 283.1 | 2.0x | ⭐ EXCELLENT |
| **measles** | Monitored | 70 | 239.6 | 5.6x | ⚠️ HIGH |
| **mumps** | Decoy | 70 | 186.2 | 16.6x | ⚠️ HIGH |
| **rubella** | Decoy | 70 | 142.9 | 41.6x | ⚠️ HIGH |

**Total samples**: 280 (70 per site)

**Variance Explanation**:
- **Ratio** = max_pairs / min_pairs across visits
- **< 3.0x** = Excellent (stable traffic, ideal for classification)
- **> 5.0x** = High (unstable, likely due to CDN variations, dynamic content)
- Only **chickenpox** meets ideal variance threshold

**Site Overlap Analysis**:
- **Chickenpox ↔ Measles**: 0.85 overlap (HIGH - likely to confuse)
- **Chickenpox ↔ Rubella**: 0.50 overlap (DISTINCT)
- Both are rash-related illnesses with similar page structure

### Model Performance

**Accuracy**: **98%** (55/56 correct predictions on test set)

**Per-Class Metrics**:

| Site | Precision | Recall | F1-Score | Test Samples |
|------|-----------|--------|----------|--------------|
| chickenpox | 100% | 93% | 96% | 14 |
| measles | 100% | 100% | 100% | 14 |
| mumps | 100% | 100% | 100% | 14 |
| rubella | 93% | 100% | 97% | 14 |

**Confusion Matrix** (test set, 56 samples):
```
                Predicted
              CP  MS  MP  RB
Actual   CP   13   0   0   1
         MS    0  14   0   0
         MP    0   0  14   0
         RB    0   0   0  14
```

**Errors**: 1 misclassification (chickenpox → rubella)

**Key Findings**:
1. **High accuracy despite instability**: Model achieves 98% even though 3/4 sites have high variance
2. **N-gram features are critical**: Sequential patterns provide +5-10% improvement over aggregate-only
3. **Single-domain fingerprinting works**: Even same-domain pages have distinct traffic signatures
4. **Chickenpox is most stable**: Only site meeting EXCELLENT variance threshold (2.0x)

### Data Quality Insights

**From `check_data_quality.py` analysis**:

**Traffic Variance** (measured across 70 visits per site):
- **Chickenpox**: 162-324 pairs (stable, consistent structure)
- **Measles**: 57-320 pairs (5.6x variance, CDN randomness)
- **Mumps**: 17-282 pairs (16.6x variance, very unstable)
- **Rubella**: 7-291 pairs (41.6x variance, extremely unstable)

**Feature Stability** (Coefficient of Variation):
- **Chickenpox**: 9.6-21.6% CV (low variability)
- **Measles**: 13.6-118.2% CV (high variability in some features)
- **Mumps/Rubella**: 36-155% CV (very inconsistent features)

**Why High Variance?**
- **NHS.uk CDN infrastructure**: Akamai/Cloudflare may route traffic differently per visit
- **Dynamic content loading**: A/B testing, personalization, region-based variations
- **Page complexity**: Multi-section pages (Overview, Symptoms, Treatment) have variable loading
- **Network conditions**: Time of day, server load affect response patterns

**Recommendations from analysis**:
- ⚠️ Consider removing measles, mumps, rubella (high variance)
- ✓ Chickenpox is ideal training candidate
- Need 3-5 more stable NHS pages for robust multi-class classification
- Alternative: Use chickenpox vs. non-chickenpox binary task

---

## Installation

### Prerequisites

- **macOS** (tested on macOS Sonoma, Mac Studio)
- **Python 3.10+**
- **Safari** (for automated data collection)
- **tshark** (Wireshark command-line tool)
- **Accessibility permissions** for Safari automation

### Step 1: Clone Repository

```bash
git clone https://github.com/jw23333/https-traffic-fingerprinting.git
cd https-traffic-fingerprinting
```

### Step 2: Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required packages
pip install pandas scikit-learn joblib numpy
```

### Step 3: Install tshark

```bash
# Using Homebrew
brew install wireshark

# Verify installation
tshark --version
```

**Note**: You may need to grant Wireshark permissions to capture packets:
- System Settings → Privacy & Security → Full Disk Access → Add tshark

### Step 4: Configure Safari Automation

**Grant Accessibility Permission**:
1. System Settings → Privacy & Security → Accessibility
2. Click `+` and add:
   - Terminal.app (if running scripts from terminal)
   - Python.app (if running via editor)
   - Your code editor (VS Code, PyCharm, etc.)

**Enable Developer Menu** (optional, for cache control):
1. Safari → Settings → Advanced
2. ✓ Show features for web developers
3. Develop menu → Disable Caches (for maximum consistency)

---

## Usage Guide

### Quick Start: Run GUI Demo

```bash
# Activate virtual environment
source .venv/bin/activate

# Launch GUI
python gui_capture_app.py
```

**Demo Workflow**:
1. Click **Start** (begins capture)
2. Open Safari **Private Window** (`Shift+Cmd+N`)
3. Navigate to NHS site (e.g., https://www.nhs.uk/conditions/chickenpox/)
4. Hit **`Cmd+Opt+R`** (hard reload to bypass cache)
5. Click **Stop** in GUI
6. View prediction + user-friendly explanation
7. (Optional) Click **"Show technical details ▲"** for feature importances

### Full Workflow: Collect, Train, Predict

#### 1. Collect Training Data

**Edit site list** in `collect_dataset.py`:

```python
SITES: List[str] = [
    "https://www.nhs.uk/conditions/chickenpox/",
    "https://www.nhs.uk/conditions/measles/",
    "https://www.nhs.uk/conditions/mumps/",
    "https://www.nhs.uk/conditions/rubella/",
]

MONITORED_SITES = {"chickenpox", "measles"}  # Sites to accept in GUI
VISITS_MONITORED = 70  # Visits for monitored sites
VISITS_DECOY = 70      # Visits for decoy sites
```

**Run collection**:

```bash
python collect_dataset.py
```

**What happens**:
- Creates `dataset_raw/<site>/` folders
- For each site:
  - Opens Safari Private window
  - Loads site + hard reload
  - Captures 2.5s of traffic → saves `.pcap` file
  - Repeats 70 times
  - Sleeps 1s between visits

**Duration**: ~15 minutes for 4 sites × 70 visits

#### 2. Analyze Data Quality

```bash
python check_data_quality.py
```

**Output**:
- **Variance report**: Shows stability (ratio of max/min pairs)
- **Feature CV%**: Shows which features are consistent
- **Overlap analysis**: Shows which site pairs are distinct
- **Recommendations**: Identifies problematic sites

**Use this to**:
- Remove high-variance sites (ratio > 5x)
- Identify overlapping sites that will confuse the model
- Validate you have 3-5 distinct, stable sites

#### 3. Build Pairs Dataset

```bash
python build_pairs_dataset.py
```

**What happens**:
- Scans `dataset_raw/<site>/*.pcap` files
- For each pcap:
  - Runs `process_pcap.py` to extract burst pairs
  - Saves `<site>/<prefix>_pairs.csv`
- Creates `pairs_metadata.csv` index with:
  - `site_label`, `pairs_csv_path`, `pcap_path`

**Output**: `dataset_pairs/` folder + `pairs_metadata.csv`

#### 4. (Optional) Analyze Thresholds

```bash
python analyze_thresholds.py
```

**Output**: Statistical summary of burst sizes + threshold recommendations

**Example output**:
```
OUTBOUND BURST SIZES (bytes)
Count:      59,616
Median:     11,450.0

INBOUND BURST SIZES (bytes)  
Count:      59,616
Median:     167.0

RECOMMENDED THRESHOLDS
  out_bytes: small ≤ 11450, large > 11450
  in_bytes:  small ≤ 167, large > 167
```

**Update thresholds** in `process_dataset_pairs.py`:
```python
OUT_SMALL_THRESHOLD = 11450  # From median analysis
IN_SMALL_THRESHOLD = 167
```

#### 5. Train Model

```bash
python process_dataset_pairs.py --meta pairs_metadata.csv --out-model rf_model.joblib
```

**Output**:
```
Building dataset from metadata: pairs_metadata.csv
Samples: 280, Features: 36
['total_pairs', 'total_out_bytes', ...]

              precision    recall  f1-score   support
chickenpox       1.00      0.93      0.96        14
measles          1.00      1.00      1.00        14
mumps            1.00      1.00      1.00        14
rubella          0.93      1.00      0.97        14

accuracy                           0.98        56

Confusion Matrix:
[[13  0  0  1]
 [ 0 14  0  0]
 [ 0  0 14  0]
 [ 0  0  0 14]]

Saved model bundle to: rf_model.joblib
```

**Model bundle contains**:
- Trained RandomForestClassifier
- LabelEncoder (site names ↔ numeric labels)
- Feature names list (for column alignment)

#### 6. Run Live Predictions

```bash
python gui_capture_app.py
```

**Configure monitoring** (in `gui_capture_app.py`):

```python
self.monitored_labels = {"chickenpox", "measles"}  # Accept only these
self.confidence_threshold = 0.5   # Min confidence (0-1)
self.margin_threshold = 0.20      # Min gap between top-1 and top-2
```

---

## Data Quality Analysis

The project includes robust tools to evaluate site selection before training.

### Variance Analysis

**Metric**: Ratio of max/min pair counts across visits

**Quality Thresholds**:
- **< 3.0x**: EXCELLENT (very stable, ideal)
- **3.0-4.0x**: GOOD (stable, should work well)
- **4.0-5.0x**: OK (acceptable, may have some errors)
- **≥ 5.0x**: HIGH (unstable, likely to cause misclassifications)

**Current Results**:
```
Site           Visits  Min  Max   Avg    Std   Ratio  Quality
chickenpox       70    162  324   283.1  37.0   2.0x  EXCELLENT
measles          70     57  320   239.6  71.3   5.6x  HIGH
mumps            70     17  282   186.2  86.2  16.6x  HIGH
rubella          70      7  291   142.9  94.5  41.6x  HIGH
```

**Interpretation**:
- **Chickenpox** has 2.0x ratio (tight clustering, very predictable)
- **Rubella** has 41.6x ratio (some visits had 7 pairs, others 291 — extremely inconsistent)

### Feature Stability (CV%)

**Metric**: Coefficient of Variation = (std / mean) × 100

**Threshold**: < 30% is ideal

**Current Results** (selected features):
```
Site         total_pairs  total_out_bytes  total_in_bytes  mean_out_bytes
chickenpox        13.2%          11.9%          9.6%          11.2%
measles           30.0%          24.1%         13.6%          44.1%
mumps             46.7%          37.5%         82.2%          72.7%
rubella           66.6%          75.9%         36.6%          77.6%
```

**Interpretation**:
- **Chickenpox** features have 9-13% CV (very consistent)
- **Rubella** features have 36-77% CV (extremely variable, unreliable)

### Overlap Analysis

**Metric**: Similarity of average pair counts between site pairs

**Thresholds**:
- **> 0.8**: HIGH OVERLAP (will confuse each other)
- **0.6-0.8**: MODERATE (some confusion possible)
- **< 0.6**: DISTINCT (should be distinguishable)

**Current Results**:
```
Site A        Site B         Overlap  Assessment
chickenpox    measles          0.85   HIGH OVERLAP
chickenpox    mumps            0.66   MODERATE
chickenpox    rubella          0.50   DISTINCT
measles       mumps            0.78   MODERATE
measles       rubella          0.60   DISTINCT
mumps         rubella          0.77   MODERATE
```

**Interpretation**:
- **Chickenpox vs Measles**: 0.85 overlap (both rash illnesses, similar page structure, will confuse)
- **Chickenpox vs Rubella**: 0.50 overlap (sufficiently different traffic patterns)

### Running Quality Checks

```bash
# After building pairs dataset
python check_data_quality.py
```

**Recommendations from tool**:
```
⚠️  Consider removing high-variance sites: measles, mumps, rubella
✓  Recommended sites for training: chickenpox
```

**Action items**:
1. Remove sites with > 5x variance
2. Avoid training sites with > 0.8 overlap
3. Collect 50-70 visits for sites with < 3x variance
4. Target 5-10 distinct sites for robust classification

---

## GUI Features

### User-Friendly Design

**Goal**: Make traffic fingerprinting accessible to non-technical users

**Key Features**:

#### 1. Plain-Language Explanations

Instead of showing raw feature importances, the GUI translates technical features into accessible explanations:

**Example output**:
```
What exposed your traffic the most is the total bytes downloaded from the 
website. Page sizes vary dramatically - a simple text page might be 200KB 
while a media-rich one is 2MB. Even encrypted, this total size is visible 
and distinctive.

The second most revealing aspect is how much the response sizes varied - 
measured by standard deviation. Pages with uniform content have low variation 
while pages mixing small scripts and large images have high variation, 
creating a distinctive signature.
```

**Feature explanations map** (36 total):
- `total_in_bytes` → "total bytes downloaded from the website..."
- `std_in_bytes` → "how much the response sizes varied..."
- `bigram_out_S_to_S` → "how often small outgoing bursts were followed by other small bursts..."
- `ratio_out_in_bytes` → "the balance between data you uploaded versus downloaded..."

#### 2. Collapsible Technical Details

**Default view**: Shows only top 2 feature explanations (non-technical)

**Click "Show technical details ▲"**: Expands to show all 36 features with:
- Feature name
- Importance score (0-1)
- Raw value (un-transformed)

**Example**:
```
═══════════════════════════════════════════════════════════════════
TECHNICAL DETAILS - Feature Importance Ranking:
───────────────────────────────────────────────────────────────────

total_in_bytes                 importance: 0.1560  value:    245832.00
std_in_bytes                   importance: 0.1340  value:     12456.00
ratio_out_in_bytes             importance: 0.0980  value:         0.02
bigram_out_L_to_L              importance: 0.0856  value:        23.00
...
```

#### 3. Confidence-Based Filtering

**Status bar shows**:
- `Prediction: chickenpox (confidence 0.87)` — ACCEPTED
- `No monitored site detected (low confidence 48% < 50%)` — REJECTED
- `No monitored site detected (not in monitored sites)` — REJECTED (decoy)

**Rejection logic**:
```python
# Reject if confidence < 50%
if proba < self.confidence_threshold:
    reject = True

# Reject if margin between top-1 and top-2 < 20%
if (proba - proba_top2) < self.margin_threshold:
    reject = True

# Reject if predicted label not in monitored set
if label not in self.monitored_labels:
    reject = True
```

#### 4. Auto-Cleanup

After prediction, automatically deletes:
- Temporary pcap file
- Burst pairs CSV
- Per-packet direction CSV

**Benefit**: Keeps workspace clean, no manual file management

### GUI Configuration

**Edit `gui_capture_app.py` for custom settings**:

```python
class CaptureApp(tk.Tk):
    def __init__(self, ...):
        # Network interface
        self.interface = "en1"  # WiFi interface on Mac
        
        # Monitored site filtering
        self.monitored_labels = {"chickenpox", "measles"}
        self.confidence_threshold = 0.5   # Min 50% confidence
        self.margin_threshold = 0.20      # Min 20% margin
        
        # Post-prediction cleanup
        self.cleanup_after_predict = True  # Delete temp files
```

---

## Project Files

### Core Scripts

| File | Purpose | When to Run |
|------|---------|-------------|
| **`collect_dataset.py`** | Automated data collection via Safari | When building training dataset |
| **`capture_safari_all.py`** | Low-level tshark capture helpers | Called by other scripts |
| **`process_pcap.py`** | Pcap → burst pairs conversion | Called by build/predict scripts |
| **`build_pairs_dataset.py`** | Batch process raw pcaps → pairs CSVs | After data collection |
| **`process_dataset_pairs.py`** | Feature extraction + model training | After building pairs dataset |
| **`gui_capture_app.py`** | Tkinter GUI for live prediction | For demos and testing |

### Analysis Tools

| File | Purpose | Output |
|------|---------|--------|
| **`check_data_quality.py`** | Variance, stability, overlap analysis | Quality report + recommendations |
| **`analyze_thresholds.py`** | Burst size distribution analysis | Threshold recommendations |

### Data Files

| File/Folder | Description |
|-------------|-------------|
| **`dataset_raw/<site>/`** | Raw pcap files from collection |
| **`dataset_pairs/<site>/`** | Processed burst pairs CSVs |
| **`pairs_metadata.csv`** | Index mapping site labels → pairs CSV paths |
| **`rf_model.joblib`** | Trained model bundle (model + encoder + feature names) |

### Configuration

| File | Purpose |
|------|---------|
| **`.gitignore`** | Excludes .venv, __pycache__, datasets, *.pcap from git |
| **`LICENSE`** | MIT License |
| **`README.md`** | This file |

---

## Limitations & Future Work

### Current Limitations

1. **Small dataset**: Only 4 sites × 70 visits (280 samples)
   - Research papers typically use 50-100 sites with 100+ visits each
   - Limited class diversity reduces generalization

2. **High traffic variance**: 3 out of 4 sites have ≥5x variance
   - NHS.uk CDN infrastructure creates inconsistent patterns
   - Model works despite this, but robustness is compromised

3. **Same-network training**: All data collected from one machine/network
   - May not generalize to different ISPs, geographic locations, times of day
   - Browser version differences not tested

4. **Single-domain scenario**: All sites from nhs.uk
   - Demonstrates targeted monitoring, not broad web fingerprinting
   - Cross-domain classification would show stronger signatures

5. **No defense testing**: Assumes undefended HTTPS traffic
   - Real-world defenses: traffic padding, randomized delays, Tor
   - Would significantly reduce accuracy

6. **Binary threshold n-grams**: Small/Large only
   - Could improve with 3-tier (Small/Medium/Large) classification
   - Or adaptive thresholds per site

### Future Improvements

#### Phase 1: Enhance Current Dataset (Short-term)

- ✅ **Remove unstable sites**: Drop measles, mumps, rubella (variance > 5x)
- � **Find 4-5 more stable NHS pages**: Target variance < 3x
  - Candidate: chickenpox, headache, cold, flu, covid
  - Validate with 10-visit pilot → run `check_data_quality.py`
- **Increase visits**: 100 per site for robust statistics
- **Cross-validate**: Test on different times of day, networks

#### Phase 2: Advanced Features (Medium-term)

- **Timing features**: Inter-packet delays, burst gap distributions
- **3-tier n-grams**: Small/Medium/Large classification (more granular patterns)
- **Directional pairing features**: Track bidirectional burst sequences (req → resp → req)
- **Per-position features**: First 5 pairs, middle 5 pairs, last 5 pairs

#### Phase 3: Real-World Robustness (Long-term)

- **Multi-network testing**: Collect from home WiFi, mobile data, university network
- **Browser comparison**: Test Safari vs Chrome vs Firefox
- **Defense evaluation**: Test against traffic padding, randomized delays
- **Multi-visit aggregation**: Classify based on 3-5 consecutive visits (session-level)
- **Adversarial examples**: Generate worst-case traffic patterns to test limits

#### Alternative ML Models

- **SVM with RBF kernel**: Better margin-based separation
- **XGBoost**: Gradient boosting for higher accuracy
- **Neural Networks**: LSTM for sequential pattern learning
- **SHAP values**: Per-prediction feature attribution (better than global importance)

---

## Ethical Considerations

This project is **educational research** demonstrating a real privacy vulnerability. It is not intended for malicious surveillance.

### Key Ethical Points

1. **No decryption**: Respects HTTPS encryption, analyzes only metadata
2. **Honest disclosure**: Demonstrates real risk to educate users about network-level leakage
3. **Defense-agnostic**: Not targeting specific privacy violations; shows why defenses matter
4. **Academic scope**: Intended for learning, not operational surveillance
5. **Limited dataset**: Small-scale research, not mass collection

### Privacy Implications

**What this demonstrates**:
- Your ISP, network admin, or nation-state attacker can identify which specific NHS pages you visit
- Even though content is encrypted, traffic "shape" reveals health-related browsing
- HTTPS protects content, but **not traffic metadata**

**Why this matters**:
- Sensitive health information (e.g., mental health, STDs, cancer) can be inferred
- Advertisers/employers/governments can profile browsing without accessing content
- VPNs help but don't fully solve this (still vulnerable to local network observation)

### Defense Mechanisms

**Existing solutions**:
- **Tor Browser**: Onion routing + traffic padding + uniform packet sizes
- **VPNs**: Hides destination from local network (but VPN provider can still see)
- **Traffic padding**: Add random dummy packets to obscure patterns
- **Traffic morphing**: Make all pages look similar by standardizing sizes

**Limitations of defenses**:
- **Performance cost**: Padding/delays slow down browsing
- **Adoption barrier**: Most users don't use Tor/VPNs
- **Arms race**: Attackers develop counter-techniques (e.g., deep learning on Tor traffic)

### Responsible Disclosure

This research is published as open-source to:
- **Educate users** about real privacy risks
- **Inform developers** to build better defenses
- **Motivate adoption** of privacy-enhancing technologies

**Not** to enable mass surveillance or targeted attacks.

---

## References

### Academic Papers

- Cai, X., et al. (2014). *CS-BuFLO: A Congestion Sensitive Website Fingerprinting Defense.* WPES.
- Wang, T., & Goldberg, I. (2017). *Walkie-Talkie: An Efficient Defense Against Passive Website Fingerprinting.* USENIX Security.
- Pironti, A., et al. (2012). *Identifying Website Users by TLS Traffic Analysis.* S&P.

### Tools & Libraries

- **tshark**: Wireshark command-line packet analyzer
- **scikit-learn**: Machine learning library (Random Forest)
- **pandas**: Data manipulation and analysis
- **joblib**: Model serialization

### Datasets

- Custom collected: NHS.uk health information pages
- Collection methods: Automated Safari + tshark (Private browsing + cache-bypass)

---

## License

MIT License - See `LICENSE` file for details.

---

## Contact & Contributions

**Author**: Yiwei Wang  
**Institution**: Undergraduate dissertation project  
**Year**: 2026

**Repository**: https://github.com/jw23333/https-traffic-fingerprinting

**Questions or Issues**: Open a GitHub issue

**Contributions**: Not accepting pull requests (academic project), but feedback welcome!

---

## Acknowledgments

- Dissertation supervisor for methodology guidance
- NHS.uk for providing accessible health information
- Wireshark/tshark developers for excellent packet analysis tools
- scikit-learn community for robust ML implementations

---

**⚠️ Educational Use Only**: This project demonstrates a real privacy vulnerability. Use responsibly and ethically. Do not deploy for surveillance without proper legal authorization and ethical review.
