import sys
import os

# Resolve the absolute path to the backend directory and the project root
app_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(app_dir)
project_root = os.path.dirname(backend_dir)

# Ensure backend directory is in python path
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

# Ensure project root directory (containing the 'ml' module) is in python path
if project_root not in sys.path:
    sys.path.insert(0, project_root)
