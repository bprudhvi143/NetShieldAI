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

def clean_unsw_port(val) -> float:
    """
    Deterministically parses and cleans port values:
    - Convers hex string representations (e.g. '0x000b' -> 11.0)
    - Maps '-' and empty fields to NaN.
    - Handles floats and standard integers.
    - Invalid values are converted to NaN rather than 0.
    """
    if pd.isna(val):
        return np.nan
    val_str = str(val).strip()
    if val_str == '-' or val_str == '':
        return np.nan
    if val_str.startswith('0x') or val_str.startswith('0X'):
        try:
            return float(int(val_str, 16))
        except ValueError:
            return np.nan
    try:
        return float(val_str)
    except ValueError:
        return np.nan

class UNSWNB15Pipeline:
    def __init__(self, raw_dir: str = "c:/NetShieldAI/datasets/UNSW-NB15/raw"):
        self.raw_dir = os.path.abspath(raw_dir)
        
    def get_features_headers(self) -> list:
        features_path = os.path.join(self.raw_dir, "NUSW-NB15_features.csv")
        if not os.path.exists(features_path):
            raise FileNotFoundError(f"NUSW-NB15_features.csv not found in {self.raw_dir}")
        feats_df = pd.read_csv(features_path, encoding='cp1252')
        feats_df.columns = feats_df.columns.str.strip()
        headers = feats_df["Name"].str.strip().tolist()
        headers = [h.replace(" ", "") for h in headers]
        return headers

    def discover_files(self) -> list:
        pattern = os.path.join(self.raw_dir, "UNSW-NB15_[1-4].csv")
        files = glob.glob(pattern)
        return sorted([os.path.abspath(f) for f in files])

    def load_and_clean_raw(self, sample_size: Optional[int] = 5000, random_state: int = 42) -> Tuple[pd.DataFrame, Dict[str, Any]]:
        """
        Load raw files, map headers, perform initial port cleaning and return raw combined dataframe.
        """
        headers = self.get_features_headers()
        files = self.discover_files()
        if not files:
            raise FileNotFoundError(f"No raw UNSW-NB15 CSV files found in {self.raw_dir}")

        raw_row_count = 0
        dfs = []

        rows_per_file = None
        if sample_size is not None:
            rows_per_file = sample_size // len(files)

        for f in files:
            filename = os.path.basename(f)
            # Load full file one by one to ensure representative sampling
            df_full = pd.read_csv(f, header=None, names=headers, encoding='latin1', low_memory=False)
            raw_row_count += len(df_full)

            # Sample deterministically
            if rows_per_file is not None and len(df_full) > 0:
                sample_n = min(len(df_full), rows_per_file)
                df_chunk = df_full.sample(n=sample_n, random_state=random_state)
            else:
                df_chunk = df_full

            dfs.append(df_chunk)

        df = pd.concat(dfs, ignore_index=True)
        
        # Clean sport and dsport using clean_unsw_port helper
        df['sport'] = df['sport'].apply(clean_unsw_port)
        df['dsport'] = df['dsport'].apply(clean_unsw_port)
        df['ct_ftp_cmd'] = pd.to_numeric(df['ct_ftp_cmd'], errors='coerce')

        stats = {
            "dataset_name": "UNSW-NB15",
            "raw_files": len(files),
            "raw_total_rows": raw_row_count,
            "raw_total_columns": len(headers),
            "loaded_rows": len(df)
        }

        return df, stats

    def run(
        self,
        sample_size: Optional[int] = 5000,
        random_state: int = 42,
        output_dir: str = "c:/NetShieldAI/datasets/UNSW-NB15/processed"
    ) -> Dict[str, Any]:
        """
        Execute the entire preprocessing pipeline for UNSW-NB15:
        1. Load & sample.
        2. Detect & remove duplicates.
        3. Convert inf to NaN.
        4. Validate missing attack_cat.
        5. Impute FTP/HTTP columns with 0.0 (semantic meaning).
        6. Split into train/validation/test.
        7. Fit numerical imputer on train features, apply to all.
        8. Scale/Encode (Pipelines).
        9. Save artifacts.
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
        
        # 4. attack_cat Validation
        # Clean attack_cat string values first
        df['attack_cat'] = df['attack_cat'].astype(str).str.strip()
        # In pandas, missing values are read as 'nan'
        df.loc[df['attack_cat'] == 'nan', 'attack_cat'] = np.nan

        # Counters for stats
        normal_mapped_count = 0
        inconsistent_mapped_count = 0
        
        cleaned_attack_cats = []
        for idx, row in df.iterrows():
            cat = row['attack_cat']
            lbl = row['Label']
            
            if pd.isna(cat):
                if lbl == 0:
                    cleaned_attack_cats.append('Normal')
                    normal_mapped_count += 1
                else:
                    cleaned_attack_cats.append('Unknown_Inconsistent')
                    inconsistent_mapped_count += 1
            else:
                cleaned_attack_cats.append(cat)
                
        df['attack_cat'] = cleaned_attack_cats
        
        stats["attack_cat_mappings"] = {
            "mapped_to_normal_count": normal_mapped_count,
            "inconsistencies_count": inconsistent_mapped_count
        }

        # 5. Semantic missing-value handling
        # For is_ftp_login, ct_flw_http_mthd, and ct_ftp_cmd, missing values represent 'not applicable'
        # which is equivalent to 0. We impute them with 0.0 before any general training statistic imputer.
        ftp_nulls = df['is_ftp_login'].isna().sum()
        http_nulls = df['ct_flw_http_mthd'].isna().sum()
        ftp_cmd_nulls = df['ct_ftp_cmd'].isna().sum()
        
        df['is_ftp_login'] = df['is_ftp_login'].fillna(0.0)
        df['ct_flw_http_mthd'] = df['ct_flw_http_mthd'].fillna(0.0)
        df['ct_ftp_cmd'] = df['ct_ftp_cmd'].fillna(0.0)
        
        stats["semantic_nan_imputation"] = {
            "is_ftp_login_imputed_count": int(ftp_nulls),
            "ct_flw_http_mthd_imputed_count": int(http_nulls),
            "ct_ftp_cmd_imputed_count": int(ftp_cmd_nulls)
        }

        # Check other nulls
        null_counts = df.isnull().sum()
        stats["nans_before_imputation"] = {k: int(v) for k, v in null_counts.items() if v > 0}
        
        # Target distributions
        multiclass_dist = df['attack_cat'].value_counts().to_dict()
        binary_dist = df['Label'].value_counts().to_dict()
        
        stats["multiclass_distribution"] = multiclass_dist
        stats["binary_distribution"] = binary_dist
        stats["attack_percentage"] = round((binary_dist.get(1, 0) / len(df)) * 100, 2)
        stats["num_attack_classes"] = len(multiclass_dist) - (1 if 'Normal' in multiclass_dist else 0)

        # 6. Train / Validation / Test Splitting
        # Stratified based on y_binary (Label) to ensure viability even with small samples in attack_cat.
        train_df, val_df, test_df = train_val_test_split(
            df,
            target_col='Label',
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
        
        # 7. Missing Value Imputation (Train statistics only)
        # Port columns and others can have NaNs. Fit imputer on training split.
        imputer = TrainingSetNumericImputer()
        imputer.fit(train_df, numeric_cols)
        
        train_df = imputer.transform(train_df)
        val_df = imputer.transform(val_df)
        test_df = imputer.transform(test_df)
        
        stats["imputation_medians"] = imputer.medians

        # 8. Model-Specific Preprocessing
        # Get features from schema
        classification_features = get_features_by_usage("unsw_nb15", "binary_classification")
        anomaly_features = get_features_by_usage("unsw_nb15", "anomaly_detection")
        
        # Identify numeric vs categorical features for UNSW-NB15
        # Expected categorical columns are proto, state, service
        cat_cols = ['proto', 'state', 'service']
        num_cols_class = [c for c in classification_features if c not in cat_cols]
        num_cols_anomaly = [c for c in anomaly_features if c not in cat_cols]
        
        # Fill missing values in categorical columns with 'Unknown' on all splits
        for c in cat_cols:
            train_df[c] = train_df[c].astype(str).fillna('Unknown')
            val_df[c] = val_df[c].astype(str).fillna('Unknown')
            test_df[c] = test_df[c].astype(str).fillna('Unknown')
        
        # Prepare classification features (Scaler + OHE)
        X_train_class, X_val_class, X_test_class, class_transformer = prepare_classification_features(
            train_df, val_df, test_df,
            num_cols=num_cols_class,
            cat_cols=cat_cols
        )
        
        # Prepare anomaly features (Passthrough + OHE)
        X_train_anomaly, X_val_anomaly, X_test_anomaly, anomaly_transformer = prepare_anomaly_features(
            train_df, val_df, test_df,
            num_cols=num_cols_anomaly,
            cat_cols=cat_cols
        )

        # Separate targets
        y_train_binary = train_df['Label']
        y_val_binary = val_df['Label']
        y_test_binary = test_df['Label']

        y_train_multi = train_df['attack_cat']
        y_val_multi = val_df['attack_cat']
        y_test_multi = test_df['attack_cat']

        # Separate metadata
        meta_cols = ['srcip', 'dstip', 'Stime', 'Ltime']
        meta_train = train_df[meta_cols]
        meta_val = val_df[meta_cols]
        meta_test = test_df[meta_cols]

        # 9. Filter anomaly training data to keep ONLY normal/benign records (Label == 0)
        normal_train_idx = train_df[train_df['Label'] == 0].index
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
