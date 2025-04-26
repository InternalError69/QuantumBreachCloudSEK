from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score
import pandas as pd
import joblib

# Load your dataset
data = pd.read_csv("CTU13_Scaled.csv")

# Select RAT-relevant features
features = data[[
    'TotLen Fwd Pkts', 'TotLen Bwd Pkts',
    'Fwd Pkt Len Std', 'Bwd Pkt Len Std',
    'Pkt Len Mean', 'Pkt Len Std',
    'Fwd Pkts/s', 'Bwd Pkts/s',
    'SYN Flag Cnt', 'ACK Flag Cnt',
    'Flow Duration','Idle Mean','Idle Max'
]].dropna()

# Generate pseudo-labels (attack = -1, normal = 1)
labels = [1 if i % 2 else -1 for i in range(len(features))]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    features, labels, test_size=0.3, stratify=labels, random_state=42
)

# Train the model
model = IsolationForest(contamination=0.2, random_state=42)
model.fit(X_train)

# Predict
y_pred = model.predict(X_test)

# Evaluation
print("Classification Report:")
print(classification_report(y_test, y_pred, target_names=["RAT (Outlier)", "Normal (Inlier)"]))

# Individual metrics
acc = accuracy_score(y_test, y_pred)
prec = precision_score(y_test, y_pred, pos_label=1)
rec = recall_score(y_test, y_pred, pos_label=1)
f1 = f1_score(y_test, y_pred, pos_label=1)

print(f"\nAccuracy: {acc:.4f}")
print(f"Precision (Normal): {prec:.4f}")
print(f"Recall (Normal): {rec:.4f}")
print(f"F1 Score (Normal): {f1:.4f}")

#save model
joblib.dump(model, 'isolation_forest_ctu13.pkl')
print("model saved")
