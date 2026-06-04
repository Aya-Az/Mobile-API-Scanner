#!/bin/bash
# Script de démarrage du Mobile API Vulnerability Scanner

echo "========================================"
echo "  Mobile API Vulnerability Scanner"
echo "  OWASP Mobile Top 10 & API Top 10"
echo "========================================"
echo ""

# Vérification Python
if ! command -v python3 &> /dev/null; then
    echo "Python 3 est requis. Installez-le depuis python.org"
    exit 1
fi

# Création de l'environnement virtuel si nécessaire
if [ ! -d "venv" ]; then
    echo "Création de l'environnement virtuel..."
    python3 -m venv venv
fi

# Activation venv
source venv/bin/activate 2>/dev/null || . venv/Scripts/activate 2>/dev/null

# Installation des dépendances
echo "Installation des dépendances..."
pip install -r requirements.txt -q

# Création des dossiers nécessaires
mkdir -p reports/output static

echo ""
echo "✅ Démarrage du serveur..."
echo "🌐 Interface web: http://localhost:8000"
echo "📚 Documentation API: http://localhost:8000/docs"
echo ""
echo "Appuyez sur Ctrl+C pour arrêter"
echo ""

python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
