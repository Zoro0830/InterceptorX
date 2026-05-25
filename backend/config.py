"""
InterceptorX — Central configuration
=====================================
Set LAB_MODE = True  for controlled lab environments (TLS verification disabled).
Set LAB_MODE = False for production / real bug bounty targets (TLS verification ON).

All modules import LAB_MODE from here — never hardcode it elsewhere.
"""

LAB_MODE = False  # Change to True only for local lab testing