import pandas as pd
import numpy as np
import json
import joblib
import os
import warnings
warnings.filterwarnings('ignore')

from scipy.stats import uniform, randint
from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold, cross_val_score
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score, classification_report,
    confusion_matrix, roc_auc_score, f1_score
)
import xgboost as xgb
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

# ── Paths ─────────────────────────────────────────────────────────────────────
DATA_PATH     = os.path.join('..', 'Data', 'All.csv')
FEATURES_PATH = os.path.join('..', 'reports', 'selected_features.json')
REPORTS_DIR   = os.path.join('..', 'reports')
PLOTS_DIR     = os.path.join(REPORTS_DIR, 'plots')
MODEL_PATH    = 'phishguard_model.pkl'
NAMES_PATH    = 'feature_names.pkl'
ENCODER_PATH  = 'label_encoder.pkl'

os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(PLOTS_DIR,   exist_ok=True)

# ── Load selected features ────────────────────────────────────────────────────
print("Loading selected features...")
with open(FEATURES_PATH) as fh:
    SELECTED_FEATURES = json.load(fh)
print(f"  {len(SELECTED_FEATURES)} features loaded")

# ── Load dataset ──────────────────────────────────────────────────────────────
print("Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)
print(f"  Shape: {df.shape}")

LABEL_COL = 'URL_Type_obf_Type'
if LABEL_COL not in df.columns:
    raise ValueError(f"Label column '{LABEL_COL}' not found!")

df[LABEL_COL] = df[LABEL_COL].str.strip().str.lower()
print("  Class distribution:")
print(df[LABEL_COL].value_counts().to_string())

# ── Label Encoding (Multi-class) ──────────────────────────────────────────────
le = LabelEncoder()
y = le.fit_transform(df[LABEL_COL])
joblib.dump(le, ENCODER_PATH)
print(f"\n  Multi-class Labels mapping: {dict(zip(le.classes_, le.transform(le.classes_)))}")

# ── Build feature matrix ──────────────────────────────────────────────────────
X = df[SELECTED_FEATURES].copy()
for col in X.columns:
    if X[col].dtype == 'object':
        X[col] = pd.to_numeric(X[col], errors='coerce')
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(-1, inplace=True)
print(f"\nFeature matrix: {X.shape}")

# ── Train / Test split ────────────────────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)
print(f"Train: {X_train.shape}  |  Test: {X_test.shape}")

# ── Focused RandomizedSearchCV ────────────────────────────────────────────────
print("\nStarting RandomizedSearchCV (n_iter=15, cv=5)...")

param_dist = {
    'n_estimators'     : randint(300, 600),
    'max_depth'        : randint(8, 15),
    'learning_rate'    : uniform(0.03, 0.12),
    'subsample'        : uniform(0.8, 0.2),
    'colsample_bytree' : uniform(0.5, 0.4),
    'min_child_weight' : randint(1, 5),
    'gamma'            : uniform(0, 0.3),
    'reg_alpha'        : uniform(0, 0.1),
    'reg_lambda'       : uniform(0.4, 1.2),
}

cv5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

# Multi-class XGBoost Objective
base_xgb = xgb.XGBClassifier(
    eval_metric='mlogloss',
    objective='multi:softprob',
    num_class=len(le.classes_),
    random_state=42,
    n_jobs=-1,
    tree_method='hist',
)

search = RandomizedSearchCV(
    estimator           = base_xgb,
    param_distributions = param_dist,
    n_iter              = 15,
    scoring             = 'f1_macro',
    cv                  = cv5,
    verbose             = 1,
    random_state        = 42,
    n_jobs              = -1,
    refit               = True,
)

search.fit(X_train, y_train)

print(f"\nBest CV Macro F1 score : {search.best_score_:.4f}")
print("Best params:")
for k, v in sorted(search.best_params_.items()):
    print(f"  {k:22s}: {v}")

best_model = search.best_estimator_

# ── 3-Fold CV on best model for stable confidence intervals ──────────────────
print("\nRunning 3-fold CV on best model...")
cv3 = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

cv_acc = cross_val_score(best_model, X_train, y_train, cv=cv3, scoring='accuracy',  n_jobs=-1)
cv_f1  = cross_val_score(best_model, X_train, y_train, cv=cv3, scoring='f1_macro',  n_jobs=-1)

print("\n-- 3-Fold Cross-Validation (train set) --")
print(f"  Accuracy  : {cv_acc.mean():.4f} +/- {cv_acc.std():.4f}")
print(f"  Macro F1  : {cv_f1.mean():.4f}  +/- {cv_f1.std():.4f}")

# ── Final Test Evaluation ─────────────────────────────────────────────────────
print("\nFitting on full training set...")
best_model.fit(X_train, y_train)

y_pred   = best_model.predict(X_test)
y_proba  = best_model.predict_proba(X_test)

print("\n-- Hold-out Test Set Metrics --")
print(f"  Accuracy  : {accuracy_score(y_test, y_pred):.4f}")
print(f"  Macro F1  : {f1_score(y_test, y_pred, average='macro'):.4f}")
print(f"  ROC-AUC   : {roc_auc_score(y_test, y_proba, multi_class='ovr', average='macro'):.4f}")
print()
print(classification_report(y_test, y_pred, target_names=le.classes_))

# ── Confusion matrix ──────────────────────────────────────────────────────────
cm = confusion_matrix(y_test, y_pred)
fig, ax = plt.subplots(figsize=(8, 7))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=le.classes_,
            yticklabels=le.classes_, ax=ax)
ax.set_xlabel('Predicted')
ax.set_ylabel('Actual')
ax.set_title('Confusion Matrix - Test Set (Multi-class)')
plt.tight_layout()
cm_path = os.path.join(PLOTS_DIR, 'confusion_matrix.png')
plt.savefig(cm_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"Confusion matrix saved: {cm_path}")

# ── Feature importance plot ───────────────────────────────────────────────────
fi = pd.Series(best_model.feature_importances_, index=SELECTED_FEATURES).sort_values()
fig, ax = plt.subplots(figsize=(10, 8))
fi.plot.barh(ax=ax, color='#6c63ff')
ax.set_title('XGBoost Feature Importances (Multi-class)')
ax.set_xlabel('Importance')
plt.tight_layout()
fi_path = os.path.join(PLOTS_DIR, 'feature_importances.png')
plt.savefig(fi_path, dpi=150, bbox_inches='tight')
plt.close()
print(f"Feature importance plot saved: {fi_path}")

# ── Save Artifacts ────────────────────────────────────────────────────────────
joblib.dump(best_model, MODEL_PATH)
print(f"\nModel saved: {MODEL_PATH}")

joblib.dump(SELECTED_FEATURES, NAMES_PATH)
print(f"Features saved: {NAMES_PATH}")

print("\nDone.")
