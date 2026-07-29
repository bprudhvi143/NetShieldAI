import os
import glob
import pandas as pd
import numpy as np
from typing import Tuple, Dict, Any, Optional
from ml.preprocessing.common import (
    normalize_column_names,
    remove_duplicate_rows,
    handle_inf_values,
    TrainingSetNumericImputer,
    train_val_test_split,
    prepare_classification_features,
    prepare_anomaly_features
)
from ml.features.feature_schema import get_features_by_usage

# Normalized naming mapping for corrupted characters in labels
LABEL_CLEAN_MAP = {
    'Web Attack  Brute Force': 'Web Attack - Brute Force',
    'Web Attack  XSS': 'Web Attack - XSS',
    'Web Attack  Sql Injection': 'Web Attack - Sql Injection'
}

class CICIDS2017Pipeline:
    def __init__(self, raw_dir: str = "c:/NetShieldAI/datasets/CICIDS2017/raw"):
        self.raw_dir = os.path.abspath(raw_dir)
        
    def discover_files(self) -> list:
        pattern = os.path.join(self.raw_dir, "*.csv")
        files = glob.glob(pattern)
        return sorted([os.path.abspath(f) for f in files])

    def load_and_clean_raw(self, sample_size: Optional[int] = 5000, random_state: int = 42) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Load raw files, perform initial cleaning (whitespaces, dropping Fwd Header Length.1),
        sample if sample_size is set, and return raw combined dataframe and statistics.
        """
        files = self.discover_files()
        if not files:
            raise FileNotFoundError(f"No raw CICIDS2017 CSV files found in {self.raw_dir}")

        raw_row_count = 0
        dfs = []

        # Determine rows to read per file for sample
        rows_per_file = None
        if sample_size is not None:
            rows_per_file = sample_size // len(files)

        for f in files:
            filename = os.path.basename(f)
            # Load full file one by one to ensure representative sampling
            df_full = pd.read_csv(f, encoding='latin1', low_memory=False)
            raw_row_count += len(df_full)
            
            # Normalize column names immediately
            df_full = normalize_column_names(df_full)

            # Sample deterministically
            if rows_per_file is not None and len(df_full) > 0:
                sample_n = min(len(df_full), rows_per_file)
                df_chunk = df_full.sample(n=sample_n, random_state=random_state)
            else:
                df_chunk = df_full

            dfs.append(df_chunk)

        df = pd.concat(dfs, ignore_index=True)
        
        # Clean labels
        if 'Label' in df.columns:
            df['Label'] = df['Label'].astype(str).str.strip()
            df['Label'] = df['Label'].replace(LABEL_CLEAN_MAP)

        # Confirm duplicate removal of duplicate column
        removed_duplicate_col = False
        if 'Fwd Header Length.1' in df.columns:
            df = df.drop(columns=['Fwd Header Length.1'])
            removed_duplicate_col = True

        stats = {
            "dataset_name": "CICIDS2017",
            "raw_files": len(files),
            "raw_total_rows": raw_row_count,
            "raw_total_columns": 79,
            "removed_duplicate_col": removed_duplicate_col,
            "loaded_rows": len(df)
        }

        return df, stats

    def run(
        self,
        sample_size: Optional[int] = 5000,
        random_state: int = 42,
        output_dir: str = "c:/NetShieldAI/datasets/CICIDS2017/processed"
    ) -> Dict[str, Any]:
        """
        Execute the entire preprocessing pipeline for CICIDS2017:
        1. Load & sample data.
        2. Detect & remove duplicates.
        3. Convert inf to NaN.
        4. Split into train/validation/test splits.
        5. Fit numerical imputer on training set, apply to all splits.
        6. Apply scaling/encoding.
        7. Save artifacts.
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # 1. Load and clean raw
        df, stats = self.load_and_clean_raw(sample_size=sample_size, random_state=random_state)
        
        # 2. Duplicate row handling (before splitting)
        df, duplicates_removed = remove_duplicate_rows(df)
        stats["duplicates_removed"] = duplicates_removed
        stats["processed_row_count"] = len(df)
        
        # 3. Handle infinite values (convert to NaN)
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        df = handle_inf_values(df, numeric_cols)
        
        # Count NaNs before imputation
        null_counts = df.isnull().sum()
        stats["nans_before_imputation"] = {k: int(v) for k, v in null_counts.items() if v > 0}
        
        # 4. Target extraction & binary/multiclass target definitions
        # Target classes
        df['Label_multiclass'] = df['Label'] # Multi-class target (original string label)
        df['Label_binary'] = (df['Label'] != 'BENIGN').astype(int) # Binary target (0 normal, 1 attack)
        
        # Target distribution
        multiclass_dist = df['Label_multiclass'].value_counts().to_dict()
        binary_dist = df['Label_binary'].value_counts().to_dict()
        
        stats["multiclass_distribution"] = multiclass_dist
        stats["binary_distribution"] = binary_dist
        stats["attack_percentage"] = round((binary_dist.get(1, 0) / len(df)) * 100, 2)
        stats["num_attack_classes"] = len(multiclass_dist) - (1 if 'BENIGN' in multiclass_dist else 0)

        # 5. Train / Validation / Test Splitting
        # We perform stratified split based on y_binary by default for the baseline pipeline
        # to ensure viability even with small samples. If user specifies, they can stratify on multiclass.
        train_df, val_df, test_df = train_val_test_split(
            df,
            target_col='Label_binary',
            train_ratio=0.7,
            val_ratio=0.15,
            test_ratio=0.15,
            random_state=random_state,
            stratify=True
        )

        stats["split_counts"] = {
            "train": len(train_df),
            "validation": len(val_df),
            "test": len(test_df)
        }
        
        # 6. Missing Value Imputation (Train statistics only)
        imputer = TrainingSetNumericImputer()
        imputer.fit(train_df, numeric_cols)
        
        train_df = imputer.transform(train_df)
        val_df = imputer.transform(val_df)
        test_df = imputer.transform(test_df)
        
        # Save imputer parameters to stats
        stats["imputation_medians"] = imputer.medians

        # 7. Model-Specific Preprocessing
        # Get features from schema
        classification_features = get_features_by_usage("cicids2017", "binary_classification")
        anomaly_features = get_features_by_usage("cicids2017", "anomaly_detection")
        
        # Prepare classification features (Standard Scaled)
        X_train_class, X_val_class, X_test_class, class_transformer = prepare_classification_features(
            train_df, val_df, test_df,
            num_cols=classification_features,
            cat_cols=[] # No categorical columns in CICIDS2017
        )
        
        # Prepare anomaly features (Passthrough, no scaling)
        X_train_anomaly, X_val_anomaly, X_test_anomaly, anomaly_transformer = prepare_anomaly_features(
            train_df, val_df, test_df,
            num_cols=anomaly_features,
            cat_cols=[]
        )

        # Extract Targets
        y_train_binary = train_df['Label_binary']
        y_val_binary = val_df['Label_binary']
        y_test_binary = test_df['Label_binary']

        y_train_multi = train_df['Label_multiclass']
        y_val_multi = val_df['Label_multiclass']
        y_test_multi = test_df['Label_multiclass']

        # No metadata columns for CICIDS2017, but we create empty placeholder metadata files
        # to maintain structure consistency.
        meta_train = pd.DataFrame(index=train_df.index)
        meta_val = pd.DataFrame(index=val_df.index)
        meta_test = pd.DataFrame(index=test_df.index)

        # 8. Filter anomaly training data to keep ONLY normal/benign records (Label_binary == 0)
        # Isolation Forest is trained only on benign traffic!
        normal_train_idx = train_df[train_df['Label_binary'] == 0].index
        X_train_anomaly_filtered = X_train_anomaly.loc[normal_train_idx]
        
        stats["anomaly_train_count"] = len(X_train_anomaly_filtered)

        # Save Processed Splits
        X_train_class.to_csv(os.path.join(output_dir, "X_train_class.csv"), index=True)
        X_val_class.to_csv(os.path.join(output_dir, "X_val_class.csv"), index=True)
        X_test_class.to_csv(os.path.join(output_dir, "X_test_class.csv"), index=True)

        X_train_anomaly_filtered.to_csv(os.path.join(output_dir, "X_train_anomaly.csv"), index=True)
        X_val_anomaly.to_csv(os.path.join(output_dir, "X_val_anomaly.csv"), index=True)
        X_test_anomaly.to_csv(os.path.join(output_dir, "X_test_anomaly.csv"), index=True)

        y_train_binary.to_csv(os.path.join(output_dir, "y_train_binary.csv"), index=True)
        y_val_binary.to_csv(os.path.join(output_dir, "y_val_binary.csv"), index=True)
        y_test_binary.to_csv(os.path.join(output_dir, "y_test_binary.csv"), index=True)

        y_train_multi.to_csv(os.path.join(output_dir, "y_train_multiclass.csv"), index=True)
        y_val_multi.to_csv(os.path.join(output_dir, "y_val_multiclass.csv"), index=True)
        y_test_multi.to_csv(os.path.join(output_dir, "y_test_multiclass.csv"), index=True)

        meta_train.to_csv(os.path.join(output_dir, "meta_train.csv"), index=True)
        meta_val.to_csv(os.path.join(output_dir, "meta_val.csv"), index=True)
        meta_test.to_csv(os.path.join(output_dir, "meta_test.csv"), index=True)

        return stats, class_transformer, anomaly_transformer
