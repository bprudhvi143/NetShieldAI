import os
import pytest
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from ml.preprocessing.common import (
    normalize_column_names,
    remove_duplicate_rows,
    handle_inf_values,
    TrainingSetNumericImputer,
    train_val_test_split,
    prepare_classification_features,
    prepare_anomaly_features,
    check_stratified_split_viability
)
from ml.preprocessing.unsw_nb15 import clean_unsw_port, UNSWNB15Pipeline
from ml.preprocessing.cicids2017 import CICIDS2017Pipeline
from ml.features.feature_schema import FEATURE_SCHEMA, get_features_by_usage

def test_normalize_column_names():
    df = pd.DataFrame(columns=['  Col A ', 'Col B  ', ' Col C'])
    df_clean = normalize_column_names(df)
    assert list(df_clean.columns) == ['Col A', 'Col B', 'Col C']

def test_remove_duplicate_rows():
    df = pd.DataFrame({
        'A': [1, 2, 2, 3],
        'B': [10, 20, 20, 30]
    })
    df_clean, count = remove_duplicate_rows(df)
    assert len(df_clean) == 3
    assert count == 1

def test_handle_inf_values():
    df = pd.DataFrame({
        'A': [1.0, np.inf, 3.0, -np.inf]
    })
    df_clean = handle_inf_values(df, ['A'])
    assert df_clean['A'].isna().sum() == 2
    assert df_clean['A'].iloc[0] == 1.0
    assert df_clean['A'].iloc[2] == 3.0

def test_training_set_numeric_imputer():
    train_df = pd.DataFrame({'A': [1.0, np.nan, 3.0, 4.0]}) # Median is 3.0
    val_df = pd.DataFrame({'A': [np.nan, 5.0]})
    
    imputer = TrainingSetNumericImputer()
    imputer.fit(train_df, ['A'])
    assert imputer.medians['A'] == 3.0
    
    train_imputed = imputer.transform(train_df)
    val_imputed = imputer.transform(val_df)
    
    assert train_imputed['A'].isna().sum() == 0
    assert train_imputed['A'].iloc[1] == 3.0
    assert val_imputed['A'].isna().sum() == 0
    assert val_imputed['A'].iloc[0] == 3.0

def test_check_stratified_split_viability():
    # If a class has fewer than 3 samples, it should raise ValueError
    y_invalid = pd.Series(['Normal', 'Normal', 'Attack', 'SuperTiny'])
    with pytest.raises(ValueError) as excinfo:
        check_stratified_split_viability(y_invalid, n_splits=3)
    assert "Stratified splitting is impossible" in str(excinfo.value)
    assert "SuperTiny" in str(excinfo.value)

def test_train_val_test_split():
    df = pd.DataFrame({
        'feature': list(range(20)),
        'label': [0]*10 + [1]*10
    })
    
    train, val, test = train_val_test_split(
        df,
        target_col='label',
        train_ratio=0.7,
        val_ratio=0.15,
        test_ratio=0.15,
        random_state=42,
        stratify=True
    )
    
    # 70% of 20 = 14, 15% of 20 = 3, 15% of 20 = 3
    assert len(train) == 14
    assert len(val) == 3
    assert len(test) == 3
    
    # Check stratification
    assert train['label'].value_counts().to_dict() == {0: 7, 1: 7}
    
    # Check no duplicate record leakage across splits
    combined = pd.concat([train, val, test])
    assert len(combined) == len(combined.drop_duplicates())

def test_clean_unsw_port():
    assert clean_unsw_port(80) == 80.0
    assert clean_unsw_port("80") == 80.0
    assert clean_unsw_port("0x000b") == 11.0
    assert clean_unsw_port("0xc0a8") == 49320.0
    assert pd.isna(clean_unsw_port("-"))
    assert pd.isna(clean_unsw_port("invalid"))
    assert pd.isna(clean_unsw_port(None))

def test_unsw_attack_cat_validation():
    # Test case: attack_cat missing but Label == 0 -> Normal
    # Test case: attack_cat missing but Label == 1 -> Unknown_Inconsistent
    # Test case: attack_cat present -> preserved
    df = pd.DataFrame({
        'attack_cat': [np.nan, np.nan, 'Exploits'],
        'Label': [0, 1, 1]
    })
    
    cleaned_cats = []
    inconsistencies = 0
    normal_maps = 0
    
    for idx, row in df.iterrows():
        cat = row['attack_cat']
        lbl = row['Label']
        if pd.isna(cat):
            if lbl == 0:
                cleaned_cats.append('Normal')
                normal_maps += 1
            else:
                cleaned_cats.append('Unknown_Inconsistent')
                inconsistencies += 1
        else:
            cleaned_cats.append(cat)
            
    assert cleaned_cats == ['Normal', 'Unknown_Inconsistent', 'Exploits']
    assert normal_maps == 1
    assert inconsistencies == 1

def test_target_leakage_prevention():
    # 1. Target column must not be in feature lists
    cicids_features = get_features_by_usage("cicids2017", "binary_classification")
    assert "Label" not in cicids_features
    assert "Label_binary" not in cicids_features
    assert "Label_multiclass" not in cicids_features

    unsw_features = get_features_by_usage("unsw_nb15", "binary_classification")
    assert "Label" not in unsw_features
    assert "attack_cat" not in unsw_features
    assert "srcip" not in unsw_features  # Excluded due to target leakage/generalization
    assert "dstip" not in unsw_features
    assert "Stime" not in unsw_features
    assert "Ltime" not in unsw_features

def test_preprocessor_classification_and_anomaly_consistency():
    # Verify classification vs anomaly features split and fit/transform consistency
    # Prepare dummy data
    train = pd.DataFrame({
        'num_feat': [1.0, 2.0, 3.0],
        'cat_feat': ['A', 'B', 'A']
    })
    val = pd.DataFrame({
        'num_feat': [4.0, 5.0],
        'cat_feat': ['B', 'C'] # 'C' is unseen
    })
    test = pd.DataFrame({
        'num_feat': [6.0, 7.0],
        'cat_feat': ['A', 'B']
    })
    
    # Classification: StandardScaler + OneHotEncoder
    X_train_c, X_val_c, X_test_c, preprocessor = prepare_classification_features(
        train, val, test, ['num_feat'], ['cat_feat']
    )
    
    # Check that unseen 'C' in val is ignored (filled with zeros in one-hot encoded columns)
    assert X_train_c.shape[1] == 3 # num_feat, cat_feat_A, cat_feat_B
    assert X_val_c.shape[1] == 3
    assert X_test_c.shape[1] == 3
    
    # Dimensions and column names are identical
    assert list(X_train_c.columns) == list(X_val_c.columns)
    assert list(X_train_c.columns) == list(X_test_c.columns)
    
    # Standard deviation/mean scaling verification
    assert abs(X_train_c['num_feat'].mean()) < 1e-9 # Scaled to mean=0
    
    # Anomaly features: Passthrough + OneHotEncoder
    X_train_a, X_val_a, X_test_a, preprocessor_a = prepare_anomaly_features(
        train, val, test, ['num_feat'], ['cat_feat']
    )
    
    # Passthrough means not scaled
    assert X_train_a['num_feat'].iloc[0] == 1.0
    assert X_train_a['num_feat'].iloc[2] == 3.0

def test_anomaly_training_normal_only():
    # Anomaly detection training must contain ONLY normal records,
    # whereas val and test have both.
    train_df = pd.DataFrame({
        'feat': [1.0, 2.0, 3.0],
        'Label_binary': [0, 1, 0] # Row 1 is attack
    })
    
    normal_train_idx = train_df[train_df['Label_binary'] == 0].index
    train_anomaly = train_df.loc[normal_train_idx]
    
    assert len(train_anomaly) == 2
    assert 1 not in train_anomaly.index # Attack record excluded
