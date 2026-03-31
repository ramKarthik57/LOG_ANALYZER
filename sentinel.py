"""
SENTINEL — Self-Evolving Neural Threat Intelligence Engine
===========================================================
Main entry point for the SENTINEL Forensic Intelligence Platform.

Usage:
    python sentinel.py          # Launch the GUI dashboard
    python sentinel.py --sim    # Generate simulated logs and launch
"""

import sys
import os

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sentinel.gui import SentinelGUI
from sentinel.simulator import generate_full_simulation
import tkinter as tk


def main():
    # Check for --sim flag
    if "--sim" in sys.argv:
        print("[SENTINEL] Generating simulated attack log ...")
        path = generate_full_simulation()
        print(f"[SENTINEL] Simulation saved: {path}")
        print("[SENTINEL] Launching dashboard ...")

    root = tk.Tk()
    app = SentinelGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
