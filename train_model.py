# ===============================================
# train_model.py — Cybersecurity Dashboard Project
# ===============================================
# This script:
#  1. Loads the NSL-KDD (or similar) intrusion detection dataset
#  2. Cleans and encodes data
#  3. Selects key features automatically
#  4. Trains a Random Forest model
#  5. Evaluates performance and saves results
#  6. Exports model.pkl + graphs for your report
# ===============================================

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import joblib
import os

# =============== 1️⃣ LOAD DATASET ==================
DATA_PATH = "data/nsl_kdd.csv"  # change path if needed

if not os.path.exists(DATA_PATH):
    raise FileNotFoundError("Dataset not found. Place 'nsl_kdd.csv' inside the /data folder.")

df = pd.read_csv(DATA_PATH)
print("✅ Dataset loaded successfully!")
print("Shape:", df.shape)

# =============== 2️⃣ BASIC CLEANING =================
# Try to identify the label column
possible_labels = ['label', 'class', 'attack']
label_col = None
for col in possible_labels:
    if col in df.columns:
        label_col = col
        break
if not label_col:
    label_col = df.columns[-1]  # fallback to last column

# Encode labels: 'normal' → 0, others → 1
df[label_col] = df[label_col].apply(lambda x: 0 if str(x).lower() == 'normal' else 1)

# Drop rows with missing values
df.dropna(inplace=True)

# Convert categorical columns to numeric
cat_cols = df.select_dtypes(include='object').columns
encoder = LabelEncoder()
for col in cat_cols:
    df[col] = encoder.fit_transform(df[col])

print(f"✅ Encoded categorical columns: {list(cat_cols)}")

# =============== 3️⃣ FEATURE SELECTION ===============
# If dataset is large, select top numeric columns by variance
numeric_cols = df.select_dtypes(include=np.number).columns.tolist()
numeric_cols.remove(label_col)
# take top 10 high variance features
# Use the same 4 features as in the Flask app
top_features = ['duration', 'src_bytes', 'dst_bytes', 'protocol_type']

print("📊 Selected features for training:", top_features)

X = df[top_features]
y = df[label_col]

# =============== 4️⃣ SPLIT DATA ======================
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print("✅ Data split into training and test sets.")

# =============== 5️⃣ TRAIN MODEL =====================
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)
print("✅ Model training complete!")

# =============== 6️⃣ EVALUATE MODEL ==================
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"🎯 Model Accuracy: {accuracy:.2%}")
print("\nClassification Report:\n", classification_report(y_test, y_pred))

# =============== 7️⃣ CONFUSION MATRIX ================
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(5,4))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=['Normal', 'Attack'], yticklabels=['Normal', 'Attack'])
plt.title("Confusion Matrix - Cybersecurity Threat Detection")
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.tight_layout()
plt.savefig("confusion_matrix.png")
plt.close()
print("🖼️ Confusion matrix saved as 'confusion_matrix.png'")

# =============== 8️⃣ FEATURE IMPORTANCE CHART =========
importances = model.feature_importances_
indices = np.argsort(importances)[::-1]
plt.figure(figsize=(7,5))
sns.barplot(x=importances[indices], y=np.array(top_features)[indices])
plt.title("Top Feature Importances")
plt.xlabel("Importance Score")
plt.ylabel("Features")
plt.tight_layout()
plt.savefig("feature_importance.png")
plt.close()
print("🖼️ Feature importance plot saved as 'feature_importance.png'")

# =============== 9️⃣ SAVE TRAINED MODEL ===============
joblib.dump(model, "model.pkl")
print("💾 Model saved as 'model.pkl'")

print("\n✅ Training process completed successfully!")
print("Files generated: model.pkl, confusion_matrix.png, feature_importance.png")
