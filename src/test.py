import pandas as pd
import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

data_path = "C:/network_ai/data/"

for file in os.listdir(data_path):
    if file.endswith(".csv"):
        try:
            df = pd.read_csv(
                data_path + file,
                encoding='utf-8',
                encoding_errors='replace'
            )
            print(f"\nFile: {file}")
            print(f"Rows: {len(df)}")
            print(f"Labels:\n{df[' Label'].value_counts()}")
        except Exception as e:
            print(f"Error in {file}: {e}")