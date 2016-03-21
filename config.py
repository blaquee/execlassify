import os
import sys

PROJECT_FOLDER = os.path.dirname(os.path.abspath(__file__))
STDOUT_LOG = os.path.join(PROJECT_FOLDER, "stdout.log")
STDERR_LOG = os.path.join(PROJECT_FOLDER, "stderr.log")

FILES_FOLDER = os.path.join(PROJECT_FOLDER, "files")
sys.path.append(FILES_FOLDER)

LOGS_FOLDER = os.path.join(PROJECT_FOLDER, "logs")
sys.path.append(LOGS_FOLDER)

RESULTS_FOLDER = os.path.join(PROJECT_FOLDER, "results")
sys.path.append(RESULTS_FOLDER)

UPX_PATH = "/usr/local/bin/upx"
