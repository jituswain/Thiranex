# Phishing Email Detection Model

A scikit-learn pipeline that classifies emails as **Phishing** or **Safe**
using a combination of TF-IDF text features and hand-engineered URL /
keyword features.

## Files

| File | Purpose |
|---|---|
| `generate_dataset.py` | Builds a labeled dataset of phishing + legitimate emails (`emails_dataset.csv`). Swap this out for a real dataset — see below. |
| `features.py` | `EmailFeatureExtractor`: pulls URL/keyword/style signals out of raw text (URL count, IP-address links, shortener links, suspicious keyword count, exclamation marks, uppercase ratio, etc.) |
| `model.py` | Builds the full pipeline (TF-IDF + engineered features → RandomForest), trains it, evaluates it, saves `phishing_model.joblib` and `confusion_matrix.png`. |
| `predict_email.py` | Loads the saved model and classifies new email text. |

## Run it

```bash
pip install scikit-learn pandas numpy matplotlib joblib

python model.py            # trains + evaluates, saves the model
python predict_email.py    # classify sample emails with the saved model
python predict_email.py "Subject: Verify now\n\nClick http://192.168.0.1/login..."
```

## How classification works

1. **Text features** — `TfidfVectorizer` (unigrams + bigrams, English stop
   words removed, max 3000 features) captures wording patterns typical of
   phishing ("verify immediately", "click here", "suspended") vs. normal
   correspondence.
2. **Engineered features** — regex/heuristic signals proven useful for
   phishing detection in practice:
   - number of URLs in the email
   - whether a URL uses a raw IP address instead of a domain
   - whether a known link-shortening service is used
   - count of urgency/credential-harvesting keywords ("verify", "suspended",
     "account", "password", "bank", etc.)
   - exclamation-mark count, uppercase-letter ratio (shouty tone)
   - overall length, dollar-sign count, "attachment" mentions
3. Both feature sets are combined with `FeatureUnion` and fed into a
   `RandomForestClassifier` (`class_weight="balanced"`).
4. Evaluation reports **accuracy**, a full **classification report**
   (precision/recall/F1), and a **confusion matrix** (plotted to PNG).

## Using a real dataset

The demo dataset is synthetically generated from templates so the pipeline
runs end-to-end without external downloads — accuracy on it will look
unrealistically perfect (100%) because template phrasing is very
separable. For a meaningful benchmark, replace `emails_dataset.csv` with
a real corpus (e.g. the Nazario phishing corpus + SpamAssassin ham corpus,
or a Kaggle phishing-email dataset), keeping two columns:

```
text,label
"Subject: ...\n\nbody...",phishing
"Subject: ...\n\nbody...",safe
```

`model.py` will pick it up automatically (it only regenerates the CSV if
one isn't already present) — everything else in the pipeline is dataset
agnostic. With real, noisier data expect accuracy in the 90-97% range
rather than 100%, and it's worth trying `LogisticRegression` or
`GradientBoostingClassifier` as alternatives to `RandomForestClassifier`
for comparison.
