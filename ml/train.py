import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from xgboost import XGBClassifier

DATA_PATH = "data/PhiUSIIL_Phishing_URL_Dataset.csv"

print("Loading dataset...")
df = pd.read_csv(DATA_PATH, low_memory=False)

drop_cols = ["FILENAME", "URL", "Domain", "TLD", "Title"]

X = df.drop(columns=drop_cols + ["label"], errors="ignore")
y = df["label"]

X = X.select_dtypes(include=["number"])

print("Features:", X.shape[1])
print("Samples:", X.shape[0])

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training XGBoost model...")

model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\n===== PHISHGUARD MODEL RESULTS =====")
print(f"Accuracy : {accuracy_score(y_test, y_pred):.4f}")
print(f"Precision: {precision_score(y_test, y_pred):.4f}")
print(f"Recall   : {recall_score(y_test, y_pred):.4f}")
print(f"F1 Score : {f1_score(y_test, y_pred):.4f}")

joblib.dump(
    {
        "model": model,
        "features": X.columns.tolist()
    },
    "ml/phishguard_model.joblib"
)

print("\nModel saved: ml/phishguard_model.joblib")