import os
import sys

# Make the repo root importable so `oauth.app` resolves when pytest runs from any cwd.
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
