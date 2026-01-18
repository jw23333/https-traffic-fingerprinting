# HTTPS Traffic Fingerprinting for Website Classification

**Status:** Undergraduate dissertation (in development)

## Overview

This project demonstrates that websites can be identified from HTTPS traffic metadata alone, despite encryption. By analyzing packet sizes, directions, and timing patterns, a Random Forest classifier can predict which site a user is visiting with 82% accuracy—without decrypting the payload.

**Educational Purpose:** This research explores the privacy implications of HTTPS traffic leakage and how network-level information can expose browsing behavior. Intended for learning network security and machine learning concepts.

## System Architecture

```
User Interaction (GUI)
       ↓
Capture HTTPS Traffic (tshark) → dataset_raw/*.pcap
       ↓
Process into Burst Pairs → dataset_pairs/*_pairs.csv
       ↓
Extract Features (12 aggregate statistics + sequential n-grams)
       ↓
Train Random Forest Classifier
       ↓
GUI Prediction + Feature Importance Visualization
```

### Key Components

| File | Role |
|------|------|
| `gui_capture_app.py` | Tkinter GUI: start/stop capture, real-time prediction, feature importance table |
| `capture_safari_all.py` | Backend: tshark command builder, flexible start/stop or fixed-duration capture |
| `collect_dataset.py` | Safari automation: visits sites in private mode, forces cache-bypass reload |
| `process_pcap.py` | Converts pcap → burst pairs (direction-labeled, time-stamped) |
| `build_pairs_dataset.py` | Batch processes all raw pcaps → pairs CSVs + metadata index |
| `process_dataset_pairs.py` | Extracts 12 summary features + sequential n-gram features; trains RandomForestClassifier |
| `check_data_quality.py` | Evaluates site selection: variance (stability), overlap (distinctiveness) |

## How It Works

### 1. Data Collection
- Opens websites in Safari's private mode (no caching)
- Forces reload from origin (`Opt+Cmd+R`) to bypass all caches
- Captures only HTTPS traffic (TCP/UDP port 443) for 2.5 seconds per visit
- Repeats ~50 times per site for robust dataset

### 2. Processing: Pcap → Burst Pairs
- Extracts per-packet metadata using tshark (time, src/dst IP, packet size)
- Labels packets as "outgoing" (client → server) or "incoming" based on local IPs
- Groups consecutive same-direction packets within 50ms gap → **bursts**
- Pairs outgoing bursts with next incoming burst → **pairs**
- Each pair records: outgoing bytes/packets/duration, incoming bytes/packets/duration, timestamps

### 3. Feature Extraction

#### A) 12 Aggregate Statistics (existing)
For each capture, computes:
- **Counts:** `total_pairs`, `total_out_bytes`, `total_in_bytes`
- **Means:** `mean_out_bytes`, `mean_in_bytes`, `mean_out_pkts`, `mean_in_pkts`, `mean_out_dur`, `mean_in_dur`
- **Variability:** `std_out_bytes`, `std_in_bytes`
- **Ratio:** `ratio_out_in_bytes`

#### B) Sequential N-gram Features (new)
Manually engineered, position-independent features that capture flow patterns without relying on exact positions:
- **Bigrams (outbound/inbound):** counts for `S→S`, `S→L`, `L→S`, `L→L`
- **Trigrams (outbound):** counts for `S,S,S`, `S,S,L`, `S,L,S`, `S,L,L`, `L,S,S`, `L,S,L`, `L,L,S`, `L,L,L`
- **Counts:** `count_out_small`, `count_out_large`, `count_in_small`, `count_in_large`
- **Ratios:** `ratio_out_small`, `ratio_out_large`, `ratio_in_small`, `ratio_in_large`

Thresholds derived from dataset medians (see `analyze_thresholds.py`):
- Outbound: Small ≤ 5,458 bytes; Large > 5,458 bytes
- Inbound: Small ≤ 346 bytes; Large > 346 bytes

### 4. Training: Random Forest (200 Trees)
- Splits data 80/20 (train/test, stratified by site)
- Builds 200 decision trees, each on a bootstrap sample + random feature subset
- Trees vote; majority wins → robust to variance and overfitting
- Logs feature importances (which traffic characteristics most discriminative)

### 5. Prediction (GUI)
- User captures live traffic via GUI
- Extracts same 12 features
- Loads trained model + feature importances
- Predicts label + confidence percentage
- **Shows top 5 + all 12 features with importance scores** → educates user on information leakage

#### Hierarchical Monitoring (new)
The GUI now supports monitoring a subset of labels and rejecting unmonitored or ambiguous traffic:
- **Monitored labels:** configure a set of labels to accept (e.g., `{"wikipedia_org", "npmjs_com"}`)
- **Confidence threshold:** accept only if `max(predict_proba) ≥ 0.65` (configurable)
- **Margin check:** reject if the difference between top-1 and top-2 probabilities `< 0.20` (ambiguous)
- **Auto-reject decoys:** any prediction not in the monitored set is rejected (even with high confidence)

This turns the classifier into a safe monitoring tool: accepts monitored sites, rejects everything else.

## Results

Trained with aggregate + sequential n-gram features and a mixed set of monitored + decoy sites.

**Accuracy:** 96% across 5 websites (80/20 split)

**Per-Site Performance:**
- github.com: 100% F1, recall 6/6 (decoy)
- news.ycombinator.com: 92% F1, recall 6/6 (decoy)
- npmjs.com: 97% F1, recall 14/14 (monitored)
- wikipedia.org: 96% F1, recall 13/14 (monitored)
- youtube.com: 91% F1, recall 5/6 (decoy)

**Confusion Matrix (test set):**
- wikipedia → misclassified as news.ycombinator (1 sample)
- youtube → misclassified as npmjs (1 sample)

**Key Findings:**
- Sequential n-grams (+2–4% improvement) capture flow patterns beyond size/weight.
- Decoy training teaches boundaries: medium-sized sites are not all “npmjs”.
- Hierarchical monitoring accepts only monitored labels and safely rejects decoys/unmonitored sites via confidence + margin checks.

## Data Quality Metrics

The toolkit includes `check_data_quality.py` to evaluate candidate websites:

**Variance (Stability):**
- Ideal: < 3x (ratio of max to min pair count across visits)
- Indicates: How consistent a site's traffic pattern is
- High variance → ads, CDN randomness, A/B tests → poor classification

**Overlap (Distinctiveness):**
- Compares average traffic size between site pairs
- < 0.6 overlap = good candidates for distinct classes
- > 0.8 overlap = likely to confuse each other

## Installation

```bash
# Clone repo
git clone <repo-url>
cd <repo>

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install pandas scikit-learn joblib

# Install tshark (macOS)
brew install wireshark

# Grant accessibility permission for Safari automation
# System Settings → Privacy & Security → Accessibility → add Terminal/Python
```

## Usage

### 1. Collect Data
```bash
# Edit SITES list in collect_dataset.py, then:
python collect_dataset.py
```

### 2. Check Data Quality (Evaluate New Sites)
```bash
python check_data_quality.py
# Shows: variance, feature stability, site overlap, recommendations
```

### 3. Build Pairs Dataset
```bash
python build_pairs_dataset.py
# Outputs: dataset_pairs/*, pairs_metadata.csv
```

### 4. Train Model
```bash
python process_dataset_pairs.py --meta pairs_metadata.csv --out-model rf_model.joblib
# Outputs: rf_model.joblib (model bundle with aggregate + n-gram features)
```

### 5. Run GUI for Real-Time Prediction
```bash
python gui_capture_app.py
# Click Start → browse → Click Stop → see prediction + feature importance
```

#### Configure Hierarchical Monitoring
- Set monitored labels and thresholds in `gui_capture_app.py`:
       - `self.monitored_labels = {"wikipedia_org", "npmjs_com"}`
       - `self.confidence_threshold = 0.65`
       - `self.margin_threshold = 0.20`

With decoy training (e.g., `github.com`, `youtube.com`, `news.ycombinator.com`), the model learns boundaries so unmonitored sites are correctly rejected.

## Example Site Sets

### 5-site classification (research mode)
- docs.python.org, medium.com, npmjs.com, reuters.com, wikipedia.org → ~92–94% accuracy

### 2-site monitoring (demo mode)
- Monitored: wikipedia.org, npmjs.com (70 visits each)
- Decoys: github.com, youtube.com, news.ycombinator.com (30 visits each)
- GUI: accepts only monitored labels, rejects others via thresholds + label filtering

## Future Work

### Phase 2: Sequential Features + Decoy Training
- Integrate position-independent sequential features (n-grams) to capture flow patterns
- Add decoy sites from different categories/sizes to teach boundaries (unmonitored but included during training)
- Add 10–15 more websites from different categories (e.g., e-commerce, social media, video)
- Target websites with low variance (< 3x) and high distinctiveness (< 0.6 overlap)
- Expect accuracy improvement to 90%+ with better class separation

### Phase 3: Real-Time Multi-Visit Prediction
- Instead of single-visit classification, accumulate features across **consecutive visits**
- E.g., "User visited 3 times in 30 seconds → aggregate their traffic → predict"
- Hypothesis: temporal aggregation reduces noise, improves robustness
- Enables real-world scenario modeling (tracking user sessions)

### Optional Improvements
- Compare alternative ML models (SVM, Logistic Regression, Neural Networks)
- Add timing-based features (burst gaps, inter-packet delays)
- Test robustness across networks/times of day/browser versions
- Implement per-prediction feature attribution (SHAP values) instead of global importance
- Try `firstk` feature mode if sites show deterministic load ordering

## Limitations

1. **Small site set:** Only 5 websites; research papers typically use 50–100+
2. **Same-network training:** Collected on one macOS machine; may not generalize to different networks
3. **Aggregate-only features:** Doesn't capture request/response ordering (why `firstk` mode struggled)
4. **No adversarial defense:** Assumes undefended HTTPS traffic; doesn't evaluate against defense mechanisms
5. **Imbalanced data:** Sites with different sizes create natural class imbalance

## References

This work draws on traffic fingerprinting research:
- Website fingerprinting attacks (Cai et al., 2014; Wang et al., 2014)
- HTTPS traffic analysis (Pironti et al., 2012)
- Machine learning for network security

## Ethical Considerations

This project is **educational research** demonstrating information leakage in HTTPS. Key ethical points:

- **No decryption:** Respects encryption; only analyzes metadata
- **Honest disclosure:** Demonstrates real privacy risks to educate users and developers
- **Defense-agnostic:** Not targeting any specific privacy violation; shows why defenses matter
- **Academic scope:** Intended for learning, not surveillance

Users should be aware that their website visits leak identifying information at the network level, motivating development of privacy-enhancing technologies (e.g., traffic padding, traffic masking, Tor).

---

**Questions or feedback?** Open an issue or contact the author.
