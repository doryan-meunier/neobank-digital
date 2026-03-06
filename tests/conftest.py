"""
tests/conftest.py - Configuration pytest pour NeoBank Digital
Ajoute le répertoire racine du projet au sys.path afin que les modules
applicatifs (schemas, auth_service, accounts_service, etc.) soient importables.
"""

import sys
import os

# Ajouter le répertoire racine du projet au chemin Python
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
