# WordPress Security Scanner

Script Python pour l'audit de sécurité des sites WordPress.

## ⚠️ Avertissement Légal

**Ce script est destiné uniquement aux tests de sécurité autorisés.**

- Utilisez uniquement sur vos propres systèmes
- Obtenez une autorisation écrite avant tout test

## Fonctionnalités

- Analyse des headers HTTP
- Détection de version WordPress
- Énumération d'utilisateurs
- Scan des fichiers sensibles
- Analyse wp-content et uploads
- Détection des thèmes et plugins

## Installation

```bash

pip install requests
```

## Utilisation

```bash
# Scan basique
python wp_scanner.py https://example.com

# Avec timeout personnalisé
python wp_scanner.py example.com --timeout 15
```

## Exemple de sortie

```
🔍 WordPress Security Scanner
============================================
Target: https://example.com

🔍 Analyse des headers HTTP
----------------------------------------
  Server: nginx/1.18.0
  X-Powered-By: PHP/7.4.3
  ⚠️  XML-RPC Pingback détecté

🔍 Détection de version WordPress
----------------------------------------
  ✅ Version détectée: 6.1.1 (via /readme.html)
```

## Prérequis

- Python 3.6+
- Module `requests`

## Limitations

- Détection basée sur signatures communes
- Peut générer des faux positifs
- Limité par les protections du site cible
- Pas d'anon (Useragent / Proxy, etc.. ) -> pour le moment

## Licence

MIT License 
