import os
import json
import pandas as pd
import numpy as np
from typing import Tuple, List, Dict, Any
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

def normalize_column_names(df: pd.DataFrame) -> pd.DataFrame:
    """Strip leading and trailing whitespaces from column names."""
    df_copy = df.copy()
    df_copy.columns = df_copy.columns.str.strip()
    return df_copy

def remove_duplicate_rows(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """Detect and remove duplicate rows from a DataFrame."""
    initial_rows = len(df)
    df_clean = df.drop_duplicates()
    removed = initial_rows - len(df_clean)
    return df_clean, removed

def handle_inf_values(df: pd.DataFrame, columns: List[str]) -> pd.DataFrame:
    """Convert positive and negative infinity values to NaNs."""
    df_copy = df.copy()
    for col in columns:
        if col in df_copy.columns:
            df_copy[col] = df_copy[col].replace([np.inf, -np.inf], np.nan)
    return df_copy

class TrainingSetNumericImputer:
    """
    Imputer for numerical columns that computes median statistics
    ONLY on the training split and applies them to other splits.
    """
    def __init__(self):
        self.medians: Dict[str, float] = {}

    def fit(self, df: pd.DataFrame, columns: List[str]) -> None:
        for col in columns:
            if col in df.columns:
                # Calculate median ignoring NaNs
                val = df[col].median()
                self.medians[col] = 0.0 if pd.isna(val) else float(val)

    def transform(self, df: pd.DataFrame) -> pd.DataFrame:
        df_copy = df.copy()
        for col, median_val in self.medians.items():
            if col in df_copy.columns:
                df_copy[col] = df_copy[col].fillna(median_val)
        return df_copy

def check_stratified_split_viability(y: pd.Series, n_splits: int = 3) -> None:
    """
    Verify if each class in y has at least n_splits samples.
    Raises ValueError with details of insufficient classes if verification fails.
    """
    counts = y.value_counts(dropna=False)
    invalid_classes = counts[counts < n_splits]
    if not invalid_classes.empty:
        class_details = ", ".join([f"'{cls}': {cnt}" for cls, cnt in invalid_classes.items()])
        raise ValueError(
            f"Stratified splitting is impossible because the following classes have fewer than {n_splits} samples: {class_details}. "
            "Please increase the sample size or handle these classes explicitly."
        )

def train_val_test_split(
    df: pd.DataFrame,
    target_col: str,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    random_state: int = 42,
    stratify: bool = True
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Split the dataset into 70% Train, 15% Validation, and 15% Test.
    Performs stratification on the target column, validating class sufficiency beforehand.
    """
    if abs(train_ratio + val_ratio + test_ratio - 1.0) > 1e-9:
        raise ValueError("Split ratios must sum to 1.0")

    y = df[target_col]
    if stratify:
        check_stratified_split_viability(y, n_splits=3)

    # First split: Train vs Temp (Validation + Test)
    temp_ratio = val_ratio + test_ratio
    stratify_vector = y if stratify else None

    train_df, temp_df = train_test_split(
        df,
        train_size=train_ratio,
        random_state=random_state,
        stratify=stratify_vector
    )

    # Second split: Temp into Validation and Test
    val_temp_ratio = val_ratio / temp_ratio
    stratify_temp_vector = temp_df[target_col] if stratify else None

    val_df, test_df = train_test_split(
        temp_df,
        train_size=val_temp_ratio,
        random_state=random_state,
        stratify=stratify_temp_vector
    )

    return train_df, val_df, test_df

def prepare_classification_features(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    num_cols: List[str],
    cat_cols: List[str]
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, ColumnTransformer]:
    """
    Prepare feature matrices for classification:
    - Numerical: scaled with StandardScaler.
    - Categorical: one-hot encoded with OneHotEncoder(handle_unknown='ignore').
    Encoder/scaler fitted ONLY on the training split to prevent leakage.
    """
    # Define transformer pipeline
    numeric_transformer = Pipeline(steps=[
        ('scaler', StandardScaler())
    ])
    
    categorical_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', numeric_transformer, num_cols),
            ('cat', categorical_transformer, cat_cols)
        ],
        remainder='drop'
    )

    # Fit preprocessor on train_df features
    train_features = train_df[num_cols + cat_cols]
    preprocessor.fit(train_features)

    # Get feature names after one-hot encoding
    # We construct them carefully to ensure consistent column ordering
    encoded_feature_names = []
    if num_cols:
        encoded_feature_names.extend(num_cols)
    if cat_cols:
        ohe = preprocessor.named_transformers_['cat'].named_steps['onehot']
        cat_features = ohe.get_feature_names_out(cat_cols)
        encoded_feature_names.extend(cat_features)

    # Transform all splits
    X_train_arr = preprocessor.transform(train_df[num_cols + cat_cols])
    X_val_arr = preprocessor.transform(val_df[num_cols + cat_cols])
    X_test_arr = preprocessor.transform(test_df[num_cols + cat_cols])

    X_train = pd.DataFrame(X_train_arr, columns=encoded_feature_names, index=train_df.index)
    X_val = pd.DataFrame(X_val_arr, columns=encoded_feature_names, index=val_df.index)
    X_test = pd.DataFrame(X_test_arr, columns=encoded_feature_names, index=test_df.index)

    return X_train, X_val, X_test, preprocessor

def prepare_anomaly_features(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    test_df: pd.DataFrame,
    num_cols: List[str],
    cat_cols: List[str]
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, ColumnTransformer]:
    """
    Prepare feature matrices for Isolation Forest anomaly detection:
    - Numerical: passed through without scaling.
    - Categorical: one-hot encoded with OneHotEncoder(handle_unknown='ignore').
    Encoder fitted ONLY on the training split.
    """
    categorical_transformer = Pipeline(steps=[
        ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
    ])

    preprocessor = ColumnTransformer(
        transformers=[
            ('num', 'passthrough', num_cols),
            ('cat', categorical_transformer, cat_cols)
        ],
        remainder='drop'
    )

    # Fit preprocessor on train_df features
    train_features = train_df[num_cols + cat_cols]
    preprocessor.fit(train_features)

    # Get feature names
    encoded_feature_names = []
    if num_cols:
        encoded_feature_names.extend(num_cols)
    if cat_cols:
        ohe = preprocessor.named_transformers_['cat'].named_steps['onehot']
        cat_features = ohe.get_feature_names_out(cat_cols)
        encoded_feature_names.extend(cat_features)

    X_train_arr = preprocessor.transform(train_df[num_cols + cat_cols])
    X_val_arr = preprocessor.transform(val_df[num_cols + cat_cols])
    X_test_arr = preprocessor.transform(test_df[num_cols + cat_cols])

    X_train = pd.DataFrame(X_train_arr, columns=encoded_feature_names, index=train_df.index)
    X_val = pd.DataFrame(X_val_arr, columns=encoded_feature_names, index=val_df.index)
    X_test = pd.DataFrame(X_test_arr, columns=encoded_feature_names, index=test_df.index)

    return X_train, X_val, X_test, preprocessor
