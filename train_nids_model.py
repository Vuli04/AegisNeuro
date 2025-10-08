import pandas as pd
import numpy as np
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os
import glob

print("Starting Anomaly-Based NIDS training process...")

# --- 1. Data Loading and Preparation ---

# Path to the directory containing the CIC-IDS-2017 CSV files
data_path = r'C:\Users\Mathobela Vuli\OneDrive\Desktop\Aegisneuro\anomaly-based-network-intrusion'

try:
    # Use glob to find all CSV files in the directory
    all_files = glob.glob(os.path.join(data_path, "*.csv"))
    if not all_files:
        raise FileNotFoundError
    
    print(f"Found {len(all_files)} CSV files. Loading and concatenating...")
    df = pd.concat((pd.read_csv(f) for f in all_files), ignore_index=True)
    print("Data loaded successfully.")

except FileNotFoundError:
    print(f"Error: No CSV files found in the specified path: '{data_path}'")
    print("Please download the CIC-IDS-2017 dataset and update the path.")
    exit()

# --- 2. Data Cleaning ---

print("Cleaning data...")
# The dataset contains non-numeric labels and some infinite/NaN values.
# Clean up column names (remove leading spaces)
df.columns = df.columns.str.strip()

# Drop rows with any NaN or infinite values
df.replace([np.inf, -np.inf], np.nan, inplace=True)
df.dropna(inplace=True)

# The 'Label' column contains the attack type. We'll create a binary label: 0 for BENIGN, 1 for ANOMALY.
df['is_anomaly'] = df['Label'].apply(lambda x: 0 if x == 'BENIGN' else 1)

# --- 3. Feature Selection ---

# We will train the model on the numerical features.
# Drop the original label and any other non-numeric columns if they exist.
X = df.drop(columns=['Label', 'is_anomaly'])
y = df['is_anomaly']

# Ensure all features are numeric
X = X.select_dtypes(include=[np.number])

print(f"Using {len(X.columns)} numerical features for training.")

# --- NEW: Sub-sample the data for faster training with LOF ---
# LOF is computationally expensive. We'll take a random sample to make training feasible.
sample_frac = 0.1 # Use 10% of the data
print(f"Sub-sampling data to {sample_frac*100}% for faster training.")
X_sample = X.sample(frac=sample_frac, random_state=42)
y_sample = y.loc[X_sample.index]

# --- 4. Model Training (Unsupervised) ---

# For anomaly detection, we train the model ONLY on what is considered "normal".
X_normal = X_sample[y_sample == 0]

print(f"Training on {len(X_normal)} benign samples...")

# a. Scale the features
# It's important to scale data for distance-based and density-based algorithms.
scaler = StandardScaler()
X_normal_scaled = scaler.fit_transform(X_normal)

# b. Train the Local Outlier Factor (LOF) model
anomaly_rate = y_sample.value_counts(normalize=True).get(1, 0.01) # Use sample anomaly rate
print(f"Calculated sample anomaly rate: {anomaly_rate:.4f}")
model = LocalOutlierFactor(n_neighbors=20, contamination=anomaly_rate, novelty=True, n_jobs=-1)
model.fit(X_normal_scaled) # LOF is 'fit' on normal data for novelty detection

print("Model training complete.")

# --- 5. Model Evaluation ---

print("Evaluating model on the full dataset...")
# Now, we use the trained model to predict on the entire dataset (benign + attacks)
X_scaled = scaler.transform(X)
predictions = model.predict(X_scaled)

# The model outputs 1 for inliers (normal) and -1 for outliers (anomalies).
# We need to map these to our 0/1 label scheme for evaluation.
y_pred = [0 if p == 1 else 1 for p in predictions]

print("\nClassification Report:")
print(classification_report(y, y_pred, target_names=['Benign', 'Anomaly']))

print("\nConfusion Matrix:")
print(confusion_matrix(y, y_pred))

# --- 6. Save the Model and Scaler ---

# Create the Models directory if it doesn't exist
output_dir = 'Models'
if not os.path.exists(output_dir):
    os.makedirs(output_dir)
    print(f"Created directory: {output_dir}")

joblib.dump(model, os.path.join(output_dir, 'nids_model.pkl'))
joblib.dump(scaler, os.path.join(output_dir, 'nids_scaler.pkl'))
joblib.dump(X.columns.tolist(), os.path.join(output_dir, 'nids_feature_names.pkl'))

print(f"\nNIDS model, scaler, and feature names saved successfully to '{output_dir}' directory.")