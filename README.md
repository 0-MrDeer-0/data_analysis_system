### Installation

1. Install dependencies using Poetry:

    ```bash
    poetry install
    ```

2. Activate the virtual environment:
    ```bash
    poetry shell
    ```

### Running the Project

1. Run the main script to start the data analysis system:

    ```bash
    poetry run python main.py
    ```

2. Follow the on-screen instructions to load data and perform analysis.

---

## File Structure

```
data_analysis_system/
├── app/                    # Core application folder
│   ├── csv_data/           # Folder containing CSV files for data analysis
│   ├── password_reset/     # Templates for password reset functionality
│   ├── users_data/         # User-related data storage
│   └── main.py             # Entry point for the application
├── .gitignore              # Git ignore file for excluding unnecessary files
├── .pre-commit-config.yaml # Pre-commit hook configuration
├── poetry.lock             # Locked dependencies
├── pyproject.toml          # Poetry configuration file
└── README.md               # Project documentation
```
