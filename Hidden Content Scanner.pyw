# Double-click to launch the scanner without a console window.
import os
import runpy
import sys

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
os.chdir(here)
runpy.run_path(os.path.join(here, "app.py"), run_name="__main__")
