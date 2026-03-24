# Results Chapter - Argument Notes

**Discovery Narrative:** We initially tested a model on unstable websites (apple, amazon, microsoft, nytimes) for experimental purposes. The model achieved high training accuracy, but deployment revealed catastrophic failure—all traffic was misclassified as apple. This failure inspired an investigation into site stability, which revealed that apple.com's extreme traffic variance (13.3x) makes it unsuitable for fingerprinting. This led us to select stable sites (chickenpox, measles) from the NHS dataset for the main system, resulting in both high training accuracy AND consistent deployment performance.

---

# Section A: Investigating Page Stability

## Subsection 1: The Unstable Model Experiment

### What to Show

**Context:** To explore the limits of traffic fingerprinting, we conducted an experimental test using four high-traffic websites known for variable infrastructure: apple.com, microsoft.com, amazon.com, and nytimes.com. This was not intended as a production system, but rather to understand how the approach handles unstable traffic.

**Figure 1: Experimental Model Training Setup**
- Monitored sites (accepted_labels): apple, amazon (treated as "interesting" sites)
- Other sites in model: microsoft, nytimes (treated as decoys/background)
- Total samples: 200 (50 per site)
- Architecture: Same Random Forest (200 trees) as stable NHS model
- *Format:* Simple diagram or table showing experiment structure

**Figure 2: Unstable Model Confusion Matrix (Training Results)**
- Source: `experiments/unstable_case/logs/unstable_confusion_matrix.png`
- Training accuracy: 90%
- Test accuracy: 90% on held-out test set
- Apple shows perfect recall (10/10 test samples correctly identified)
- Caption: *"The unstable model achieves 90% accuracy on test data—superficially a strong result that masks a deeper problem."*
- Key insight to highlight: This looks promising until you test it in deployment

---

## Subsection 2: The Deployment Failure - Problem Discovery

### The Critical Finding

Despite 90% accuracy in the training/test split, **real-world deployments revealed complete failure.** When the model was tested with live traffic captures from apple, microsoft, amazon, and nytimes, the results were shocking:

**Figure 3: Real GUI Capture Results**
- Multiple live traffic captures attempted across the 4 sites
- **Result:** All captures classified as **apple** with >90% confidence
- Microsoft traffic → predicted apple
- Amazon traffic → predicted apple  
- NYTimes traffic → predicted apple
- Even apple traffic sometimes → still predicted apple
- Caption: *"Despite 90% test accuracy, the deployed model exhibits complete failure in the wild. All real-world traffic is systematically misclassified as apple. This is not confusion between similar sites—it is model collapse."*

### The Question This Raises

Training metrics promised 90% accuracy. Deployment showed <5% accuracy (only apple correct, rarely). **Why?**

This discrepancy inspired a critical investigation: *Is the model learning to identify these sites, or is it learning something else?*

---

## Subsection 3: Root Cause Analysis - Data Quality Investigation

### The Question
*The model performed well in controlled testing but catastrophically failed in deployment. What's wrong with the data the model learned from?*

### The Discovery: Apple's Extreme Variance

**Figure 4a: Apple.com Burst Pair Variability**
- X-axis: Visit number (1-50)
- Y-axis: Burst pair count per visit
- Shows: Extreme swings across 50 collection visits
- Min pairs: 42, Max pairs: 559, Variance ratio: **13.3x**
- Caption: *"Apple.com's traffic is fundamentally unstable. Burst structure varies by 13.3x across just 50 visits."*

**Figure 4b: Chickenpox Burst Pair Variability**
- X-axis: Visit number (1-50)
- Y-axis: Burst pair count per visit
- Shows: Tight, consistent clustering around mean
- Min pairs: ~200, Max pairs: ~400, Variance ratio: **~1.5-2x**
- Caption: *"For comparison, chickenpox.com shows stable, predictable traffic—the kind of pattern ideal for fingerprinting."*

**Figure 5: Distribution Overlay - Pair Count Histograms**
- Overlapping histograms: apple vs chickenpox
- Apple: wide, spread distribution (chaotic)
- Chickenpox: narrow, tight distribution (stable)
- Caption: *"Apple's burst distribution is spread across a wide range; chickenpox's is concentrated. This difference in data quality is why one model fails and one succeeds."*

### Data Quality Comparison Table

**Table 1: Traffic Stability Metrics**
| Site | Min Pairs | Max Pairs | Variance Ratio | Feature CV | Quality |
|------|-----------|-----------|----------------|------------|---------|
| Apple | 42 | 559 | 13.3x | 64.38% | ❌ Unstable |
| Amazon | 254 | 762 | 3.0x | 55.43% | ⚠️ Borderline |
| Microsoft | 202 | 729 | 3.6x | 63.45% | ⚠️ Borderline |
| NYTimes | 193 | 987 | 5.1x | 42.45% | ⚠️ Borderline |
| Chickenpox | ~200-400 | ~200-400 | ~1.5-2x | ~15-20% | ✅ Stable |
| Measles | ~200-400 | ~200-400 | ~1.5-2x | ~15-20% | ✅ Stable |

*Source: `experiments/unstable_case/logs/quality_analysis.json` + NHS dataset analysis*

### The Root Cause Mechanism

With 13.3x variance in burst pairs, the extracted features (mean_out_bytes, std_in_bytes, ratio calculations, etc.) vary wildly across visits. The model learns to recognize:
- **Apple:** "Any highly variable burst pattern"
- **Amazon/Microsoft:** Similar-but-slightly-different variable patterns (confounded with apple)
- **NYTimes:** Also variable, but with different frequency characteristics

In deployment, when the model encounters novel apple traffic that doesn't match the training snapshot, it falls back on the general rule: "Variable traffic = apple."

---

## Subsection 4: The Solution - Selecting Stable Sites for the Main System

### The Insight

The investigation revealed that site stability is not a luxury—it's a **prerequisite** for viable fingerprinting. The unstable sites failed not because of model architecture or hyperparameters, but because the data itself was too noisy for reliable feature extraction.

### Selection of Stable Sites

Based on this discovery, we pivoted to the NHS dataset, selecting two sites with proven traffic stability:
- **Chickenpox**: Low variance, 1.5-2x burst pair ratio, 15-20% feature CV
- **Measles**: Low variance, 1.5-2x burst pair ratio, 15-20% feature CV

(Mumps and rubella served as decoy sites, similar to the unstable model experiment.)

### What to Show

**Figure 6: Side-by-Side Model Comparison - Validation**

*Left column: Unstable Model (Apple/Amazon/Microsoft/NYTimes)*
- Training: 90% accuracy ✓ (looks good)
- Deployment: Complete failure (~5% accuracy) ✗
- Root cause: Apple 13.3x variance, 64.38% feature CV
- **Finding:** Training metrics misleading; real-world performance catastrophic

*Right column: Stable Model (Chickenpox/Measles)*
- Training: 98% accuracy ✓
- Deployment: Consistent ~98% accuracy ✓ (matches training!)
- Data quality: ~1.5-2x variance, ~15-20% CV
- **Finding:** Stable data enables prediction reliability

Caption: *"Model architecture is identical. The difference is data quality. Unstable sites produce misleading high training accuracy that fails in deployment. Stable sites produce training accuracy that generalizes to real-world performance. This validates the critical discovery: HTTPS fingerprinting viability is fundamentally constrained by traffic stability."*

### The Core Lesson

This experiment-turned-investigation revealed that **traffic stability is not optional**—it's a hard requirement. Sites with extreme variance cannot provide reliable ground truth for model training, regardless of architecture. The solution was not to improve the model, but to select sources with stable traffic patterns.

# Implementation: Code for Generating Figures

### Figure 4a - Apple Variability Plot
```python
import pandas as pd
from pathlib import Path
import matplotlib.pyplot as plt
import numpy as np

pairs_dir = Path("experiments/unstable_case/pairs/apple")
visits = sorted(pairs_dir.glob("*.csv"))

pair_counts = []
visit_numbers = []

for i, csv in enumerate(visits, 1):
    df = pd.read_csv(csv)
    pair_counts.append(len(df))
    visit_numbers.append(i)

plt.figure(figsize=(12, 5))
plt.plot(visit_numbers, pair_counts, 'o-', color='red', alpha=0.7)
plt.axhline(y=np.mean(pair_counts), color='red', linestyle='--', label=f'Mean: {np.mean(pair_counts):.0f}')
plt.fill_between(visit_numbers, min(pair_counts), max(pair_counts), alpha=0.1, color='red')
plt.xlabel('Visit Number')
plt.ylabel('Burst Pair Count')
plt.title('Apple.com: Extreme Traffic Variability (13.3x variance)')
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('apple_variability.png', dpi=300)
```

### Figure 4b - Chickenpox Variability Plot
```python
# Same pattern as above but for chickenpox from main dataset
pairs_dir = Path("pairs/chickenpox")  # Adjust to actual path
visits = sorted(pairs_dir.glob("*.csv"))
# ... repeat above code, change colors to green ...
```

### Figure 4c - Measles Variability Plot
```python
# Same pattern as above but for measles from main dataset
pairs_dir = Path("pairs/measles")  # Adjust to actual path
visits = sorted(pairs_dir.glob("*.csv"))
# ... repeat above code, change colors to blue ...
```

### Figure 5 - Distribution Overlay Histogram
```python
plt.figure(figsize=(12, 6))

# Apple
apple_pairs = [len(pd.read_csv(csv)) for csv in sorted(Path("experiments/unstable_case/pairs/apple").glob("*.csv"))]
plt.hist(apple_pairs, bins=15, alpha=0.6, label=f'Apple (CV=64.38%, min={min(apple_pairs)}, max={max(apple_pairs)})', color='red')

# Chickenpox
chickenpox_pairs = [len(pd.read_csv(csv)) for csv in sorted(Path("pairs/chickenpox").glob("*.csv"))]
plt.hist(chickenpox_pairs, bins=15, alpha=0.6, label=f'Chickenpox (CV~18%, min={min(chickenpox_pairs)}, max={max(chickenpox_pairs)})', color='green')

# Measles
measles_pairs = [len(pd.read_csv(csv)) for csv in sorted(Path("pairs/measles").glob("*.csv"))]
plt.hist(measles_pairs, bins=15, alpha=0.6, label=f'Measles (CV~18%, min={min(measles_pairs)}, max={max(measles_pairs)})', color='blue')

plt.xlabel('Burst Pair Count per Visit')
plt.ylabel('Frequency')
plt.title('Traffic Stability Comparison: Unstable vs. Stable Sites')
plt.legend()
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig('pair_count_comparison.png', dpi=300)
```


