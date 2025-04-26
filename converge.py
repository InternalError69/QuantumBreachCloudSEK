import pandas as pd

# Load the datasets
normal_df = pd.read_csv("CTU13_Normal_Traffic.csv")
attack_df = pd.read_csv("CTU13_Attack_Traffic.csv")

# Trim to the same size (based on smaller dataset)
min_len = min(len(normal_df), len(attack_df))
normal_df = normal_df.iloc[:min_len].reset_index(drop=True)
attack_df = attack_df.iloc[:min_len].reset_index(drop=True)

# Create an empty DataFrame with same columns
combined_df = pd.DataFrame(columns=normal_df.columns)

# Alternate attack (even index) and normal (odd index) rows
for i in range(min_len):
    combined_df = pd.concat([combined_df, attack_df.iloc[[i]], normal_df.iloc[[i]]], ignore_index=True)

# Save to a new CSV
combined_df.to_csv("CTU13_Combined_Alternating.csv", index=False)

print("✅ Combined dataset saved as 'CTU13_Combined_Alternating.csv'")
