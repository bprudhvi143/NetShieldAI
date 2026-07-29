import os
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
import pandas as pd

from app.datasets.loader import DatasetLoader
from app.services.auth_service import RoleChecker
from app.models.user import User

router = APIRouter()

# Instantiate the dataset loader
loader = DatasetLoader()

class SampleRequest(BaseModel):
    dataset_name: str = Field(..., description="Dataset name: 'cicids2017' or 'unsw_nb15'")
    sample_size: int = Field(default=5000, ge=100, le=10000, description="Size of the sample dataset")

@router.post("/sample", status_code=status.HTTP_201_CREATED)
def trigger_dataset_sampling(
    payload: SampleRequest,
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Triggers sampling (default 5,000 rows) of the selected dataset.
    Saves the output to the workspace processed folder.
    Access restricted to Security Admin or Security Analyst.
    """
    dataset_name = payload.dataset_name.lower()
    if dataset_name not in ["cicids2017", "unsw_nb15"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported dataset name. Use 'cicids2017' or 'unsw_nb15'."
        )
        
    try:
        # Load and sample the dataset
        df = loader.load_and_sample(dataset_name, target_total_rows=payload.sample_size)
        
        # Save sample to processed directory
        filename = f"{dataset_name}_sample.csv"
        save_path = loader.save_processed_dataset(df, filename)
        
        # Calculate stats
        stats = loader.get_dataset_stats(df)
        
        return {
            "message": f"Successfully generated and saved sample for {payload.dataset_name}.",
            "file_name": filename,
            "absolute_path": save_path,
            "statistics": stats
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process dataset sampling: {str(e)}"
        )

@router.get("/reports/{dataset_name}")
def get_dataset_profiling_report(
    dataset_name: str,
    analyst_user: User = Depends(RoleChecker(["Security Admin", "Security Analyst"]))
):
    """
    Generates profiling reports (statistics, nulls, class distribution, features)
    on the pre-generated sample dataset file.
    Access restricted to Security Admin or Security Analyst.
    """
    ds_name = dataset_name.lower()
    if ds_name not in ["cicids2017", "unsw_nb15"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported dataset name. Use 'cicids2017' or 'unsw_nb15'."
        )
        
    sample_file = os.path.join(loader.processed_dir, f"{ds_name}_sample.csv")
    if not os.path.exists(sample_file):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample file not found for '{dataset_name}'. Please call /datasets/sample first."
        )
        
    try:
        df = pd.read_csv(sample_file)
        
        # Profile general stats
        stats = loader.get_dataset_stats(df)
        
        # Profile missing values
        missing_report = loader.get_missing_value_report(df)
        
        # Profile class distributions
        # In CICIDS2017, the label column name is 'Label'. In UNSW-NB15 it is 'Label' or 'attack_cat'.
        label_col = "Label"
        class_report = loader.get_class_distribution(df, label_col)
        
        # If UNSW-NB15, also generate multi-class attack categories distribution
        attack_cat_report = None
        if ds_name == "unsw_nb15":
            attack_cat_report = loader.get_class_distribution(df, "attack_cat")
            
        # Profile feature summary
        feature_summary = loader.get_feature_summary(df)
        
        return {
            "dataset_name": dataset_name,
            "statistics": stats,
            "missing_value_report": missing_report,
            "class_distribution": class_report,
            "attack_categories_distribution": attack_cat_report,
            "feature_summary": feature_summary
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to compile profiling reports: {str(e)}"
        )
