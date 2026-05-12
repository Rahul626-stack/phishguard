import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import accuracy_score, classification_report, make_scorer, precision_score, recall_score, f1_score
import xgboost as xgb
import joblib
import os

print("Loading dataset...")
df = pd.read_csv('../All.csv', low_memory=False)

print("Dataset shape:", df.shape)

if 'URL_Type_obf_Type' in df.columns:
    print("Labels:", df['URL_Type_obf_Type'].unique())
    df['label'] = df['URL_Type_obf_Type'].apply(lambda x: 0 if str(x).strip().lower() == 'benign' else 1)
else:
    print("Label column not found!")
    exit(1)

drop_cols = ['URL_Type_obf_Type', 'label']
X = df.drop(columns=drop_cols)
y = df['label']

for col in X.columns:
    if X[col].dtype == 'object':
        X[col] = pd.to_numeric(X[col], errors='coerce')

X.replace([np.inf, -np.inf], np.nan, inplace=True)
X = X.fillna(-1)

print("Training model...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("Starting RandomizedSearchCV for Hyperparameter Tuning...")

param_distributions = {
    'n_estimators': [100, 200, 300, 500],
    'max_depth': [5, 10, 15, 20],
    'learning_rate': [0.01, 0.05, 0.1, 0.2],
    'subsample': [0.8, 0.9, 1.0],
    'colsample_bytree': [0.8, 0.9, 1.0]
}

xgb_base = xgb.XGBClassifier(n_jobs=-1, random_state=42)
cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)

random_search = RandomizedSearchCV(
    estimator=xgb_base,
    param_distributions=param_distributions,
    n_iter=10,
    scoring='f1',
    cv=cv,
    verbose=2,
    random_state=42,
    n_jobs=-1
)

random_search.fit(X_train, y_train)

print("\n--- Best Hyperparameters ---")
print(random_search.best_params_)

best_model = random_search.best_estimator_

print("\nEvaluating Best Model on Test Set...")
preds = best_model.predict(X_test)
acc = accuracy_score(y_test, preds)
print(f"Test Set Accuracy: {acc:.4f}")
print("\nClassification Report (Test Set):")
print(classification_report(y_test, preds))

joblib.dump(best_model, 'phishguard_model.pkl')
joblib.dump(list(X.columns), 'feature_names.pkl')

print("Model saved to phishguard_model.pkl")
