import os
import glob
import pandas as pd
import numpy as np
from typing import List, Dict, Any, Tuple

class DatasetLoader:
    """
    Reusable Dataset Loader and Profiler for NetShield AI.
    Handles discovery, low-memory sampling, statistical reporting, and validation
    for the CICIDS2017 and UNSW-NB15 network threat datasets.
    """
    def __init__(self, base_dir: str = "c:/NetShieldAI/datasets"):
        self.base_dir = os.path.abspath(base_dir)
        self.cicids_raw_dir = os.path.join(self.base_dir, "CICIDS2017/raw")
        self.unsw_raw_dir = os.path.join(self.base_dir, "UNSW-NB15/raw")
        self.processed_dir = os.path.join(self.base_dir, "processed")

        # Create processed folder if it doesn't exist
        os.makedirs(self.processed_dir, exist_ok=True)

    def discover_files(self, dataset_name: str) -> List[str]:
        """
        Locate all raw CSV files for a given dataset using glob search.
        dataset_name: 'cicids2017' or 'unsw_nb15'
        """
        if dataset_name.lower() == "cicids2017":
            pattern = os.path.join(self.cicids_raw_dir, "*.csv")
        elif dataset_name.lower() == "unsw_nb15":
            pattern = os.path.join(self.unsw_raw_dir, "UNSW-NB15_[1-4].csv")
        else:
            raise ValueError("Unsupported dataset. Choose 'cicids2017' or 'unsw_nb15'.")
        
        files = glob.glob(pattern)
        # Normalize slashes for Windows compatibility
        return [os.path.abspath(f) for f in files]

    def get_unsw_features(self) -> List[str]:
        """
        Load column headers for UNSW-NB15 from NUSW-NB15_features.csv.
        """
        features_path = os.path.join(self.unsw_raw_dir, "NUSW-NB15_features.csv")
        if not os.path.exists(features_path):
            raise FileNotFoundError(f"UNSW-NB15 features file not found: {features_path}")
        
        features_df = pd.read_csv(features_path, encoding="cp1252")
        # Strip whitespaces from column names
        features_df.columns = features_df.columns.str.strip()
        
        # In NUSW-NB15_features.csv, columns list represents names
        feature_names = features_df["Name"].str.strip().tolist()
        
        # Clean specific column typos found in the raw feature list
        # e.g., 'ct_src_ ltm' -> 'ct_src_ltm'
        feature_names = [f.replace(" ", "") for f in feature_names]
        return feature_names

    def load_and_sample(self, dataset_name: str, target_total_rows: int = 5000) -> pd.DataFrame:
        """
        Load a representative sample from the dataset CSV files without loading
        entire gigabyte files into memory.
        """
        files = self.discover_files(dataset_name)
        if not files:
            raise FileNotFoundError(f"No raw files found for dataset: {dataset_name}")

        sampled_dfs = []
        rows_per_file = target_total_rows // len(files)
        
        # If it is UNSW-NB15, load column headers from features CSV
        headers = None
        if dataset_name.lower() == "unsw_nb15":
            headers = self.get_unsw_features()

        for file_path in files:
            print(f"Loading sample from {os.path.basename(file_path)}...")
            try:
                # Read a chunk from the file
                # If UNSW-NB15, it is headerless, so we pass headers
                if dataset_name.lower() == "unsw_nb15":
                    chunk = pd.read_csv(
                        file_path, 
                        header=None, 
                        names=headers, 
                        nrows=rows_per_file * 2,  # Read twice as much to allow clean random sampling
                        encoding="cp1252",
                        low_memory=False
                    )
                else:
                    chunk = pd.read_csv(
                        file_path, 
                        nrows=rows_per_file * 2,
                        low_memory=False
                    )
                    # Clean whitespaces in column names for CICIDS2017
                    chunk.columns = chunk.columns.str.strip()

                # Clean up infinite values to NaNs
                chunk = chunk.replace([np.inf, -np.inf], np.nan)
                
                # Sample the target number of rows
                sample_size = min(len(chunk), rows_per_file)
                if sample_size > 0:
                    sampled_dfs.append(chunk.sample(n=sample_size, random_state=42))
                    
            except Exception as e:
                print(f"Error loading {file_path}: {e}")

        if not sampled_dfs:
            raise ValueError(f"Could not load any data for {dataset_name}")

        # Combine samples
        combined_df = pd.concat(sampled_dfs, ignore_index=True)
        return combined_df

    def get_dataset_stats(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Calculate general dataset statistics (total rows, columns, memory usage, types).
        """
        mem_usage_bytes = df.memory_usage(deep=True).sum()
        mem_usage_mb = round(mem_usage_bytes / (1024 * 1024), 2)
        
        dtypes_summary = df.dtypes.value_index if hasattr(df.dtypes, 'value_index') else df.dtypes.value_counts()
        dtypes_dict = {str(k): int(v) for k, v in dtypes_summary.items()}

        return {
            "num_rows": int(len(df)),
            "num_columns": int(len(df.columns)),
            "memory_usage_mb": float(mem_usage_mb),
            "data_types": dtypes_dict
        }

    def get_missing_value_report(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Identify columns with missing/NaN values and calculate percentages.
        """
        null_counts = df.isnull().sum()
        columns_with_nulls = null_counts[null_counts > 0]
        
        report = {}
        for col, count in columns_with_nulls.items():
            percentage = round((count / len(df)) * 100, 2)
            report[col] = {
                "null_count": int(count),
                "null_percentage": float(percentage)
            }
        return report

    def get_class_distribution(self, df: pd.DataFrame, label_column: str) -> Dict[str, Any]:
        """
        Determine class frequency distributions for the target label.
        """
        # Find the correct label column in a case-insensitive manner if not exact match
        matched_col = None
        for col in df.columns:
            if col.strip().lower() == label_column.strip().lower():
                matched_col = col
                break
                
        if not matched_col:
            return {"error": f"Label column '{label_column}' not found in DataFrame columns."}
            
        value_counts = df[matched_col].value_counts(dropna=False)
        total = len(df)
        
        distribution = {}
        for val, count in value_counts.items():
            label_str = str(val)
            percentage = round((count / total) * 100, 2)
            distribution[label_str] = {
                "count": int(count),
                "percentage": float(percentage)
            }
        return distribution

    def get_feature_summary(self, df: pd.DataFrame) -> Dict[str, Any]:
        """
        Generate statistical summary (mean, std, min, max) for numeric columns.
        """
        numeric_df = df.select_dtypes(include=[np.number])
        summary = {}
        
        # Describe numeric columns and fetch stats
        desc = numeric_df.describe().to_dict()
        for col, stats in desc.items():
            summary[col] = {
                "mean": float(stats["mean"]) if not np.isnan(stats["mean"]) else 0.0,
                "std": float(stats["std"]) if not np.isnan(stats["std"]) else 0.0,
                "min": float(stats["min"]) if not np.isnan(stats["min"]) else 0.0,
                "max": float(stats["max"]) if not np.isnan(stats["max"]) else 0.0,
                "unique_values": int(df[col].nunique())
            }
        return summary

    def save_processed_dataset(self, df: pd.DataFrame, filename: str) -> str:
        """
        Save the processed DataFrame as a CSV file in the processed/ directory.
        """
        save_path = os.path.join(self.processed_dir, filename)
        df.to_csv(save_path, index=False)
        return os.path.abspath(save_path)
