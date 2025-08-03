#!/usr/bin/env python3
"""
WordPress Security Scanner
Script de reconnaissance pour tests de sécurité autorisés
"""

import requests
import argparse
import json
import re
from urllib.parse import urljoin, urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys

# Désactiver les warnings SSL pour les tests
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class WordPressScanner:
    def __init__(self, target_url, timeout=10):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'WordPress Security Scanner 1.0'
        })
        
    def print_banner(self):
        print("=" * 60)
        print("🔍 WordPress Security Scanner")
        print("=" * 60)
        print(f"Target: {self.target_url}")
        print("=" * 60)
        
    def make_request(self, path="", method="GET"):
        """Effectue une requête HTTP sécurisée"""
        try:
            url = urljoin(self.target_url, path)
            response = self.session.request(
                method, url, 
                timeout=self.timeout, 
                verify=False,
                allow_redirects=True
            )
            return response
        except requests.RequestException as e:
            print(f"❌ Erreur lors de la requête {path}: {e}")
            return None
    
    def scan_headers(self):
        """Analyse les headers HTTP du serveur"""
        print("\n🔍 Analyse des headers HTTP")
        print("-" * 40)
        
        response = self.make_request()
        if not response:
            return
            
        interesting_headers = [
            'Server', 'X-Powered-By', 'X-Pingback', 'Link',
            'X-Frame-Options', 'X-Content-Type-Options', 
            'Content-Security-Policy', 'X-WP-Version'
        ]
        
        for header in interesting_headers:
            if header in response.headers:
                print(f"  {header}: {response.headers[header]}")
                
        # Vérifier le pingback WordPress
        if 'X-Pingback' in response.headers:
            print("  ⚠️  XML-RPC Pingback détecté")
    
    def detect_wordpress_version(self):
        """Détecte la version de WordPress"""
        print("\n🔍 Détection de version WordPress")
        print("-" * 40)
        
        version_indicators = [
            ('/wp-includes/version.php', r'\$wp_version = [\'"]([^\'"]+)[\'"]'),
            ('/readme.html', r'Version ([0-9.]+)'),
            ('/', r'content="WordPress ([0-9.]+)"'),
            ('/wp-admin/css/login.min.css', r'ver=([0-9.]+)'),
        ]
        
        for path, pattern in version_indicators:
            response = self.make_request(path)
            if response and response.status_code == 200:
                match = re.search(pattern, response.text)
                if match:
                    version = match.group(1)
                    print(f"  ✅ Version détectée: {version} (via {path})")
                    return version
        
        print("  ❌ Version non détectée")
        return None
    
    def scan_users(self):
        """Énumère les utilisateurs WordPress"""
        print("\n🔍 Énumération des utilisateurs")
        print("-" * 40)
        
        # Méthode 1: API REST WordPress
        users_found = self.scan_users_api()
        
        # Méthode 2: Author enumeration
        if not users_found:
            self.scan_users_author()
    
    def scan_users_api(self):
        """Scan via l'API REST WordPress"""
        endpoints = [
            '/wp-json/wp/v2/users',
            '/wp-json/wp/v2/users?per_page=100',
            '/?rest_route=/wp/v2/users'
        ]
        
        for endpoint in endpoints:
            response = self.make_request(endpoint)
            if response and response.status_code == 200:
                try:
                    users = response.json()
                    if users:
                        print(f"  ✅ {len(users)} utilisateur(s) trouvé(s) via API REST:")
                        for user in users:
                            print(f"    - ID: {user.get('id', 'N/A')}, "
                                  f"Login: {user.get('slug', 'N/A')}, "
                                  f"Nom: {user.get('name', 'N/A')}")
                        return True
                except json.JSONDecodeError:
                    continue
        
        return False
    
    def scan_users_author(self):
        """Scan par énumération d'auteurs"""
        print("  Tentative d'énumération par author ID...")
        
        for user_id in range(1, 11):  # Test des 10 premiers IDs
            response = self.make_request(f'/?author={user_id}')
            if response and response.status_code == 200:
                # Chercher le nom d'utilisateur dans l'URL de redirection
                if response.url != self.make_request().url:
                    username = urlparse(response.url).path.split('/')[-2]
                    if username:
                        print(f"    - ID {user_id}: {username}")
    
    def scan_common_files(self):
        """Scan des fichiers communs WordPress"""
        print("\n🔍 Scan des fichiers sensibles")
        print("-" * 40)
        
        sensitive_files = [
            '/readme.html',
            '/license.txt', 
            '/wp-config.php',
            '/wp-config.php.bak',
            '/wp-config-sample.php',
            '/wp-admin/install.php',
            '/wp-admin/upgrade.php',
            '/xmlrpc.php',
            '/wp-cron.php'
        ]
        
        for file_path in sensitive_files:
            response = self.make_request(file_path)
            if response:
                if response.status_code == 200:
                    print(f"  ✅ {file_path} - Accessible ({len(response.content)} bytes)")
                elif response.status_code == 403:
                    print(f"  ⚠️  {file_path} - Existe mais protégé")
    
    def scan_wp_content(self):
        """Scan du répertoire wp-content"""
        print("\n🔍 Scan wp-content et uploads")
        print("-" * 40)
        
        directories = [
            '/wp-content/',
            '/wp-content/uploads/',
            '/wp-content/themes/',
            '/wp-content/plugins/',
            '/wp-includes/',
            '/wp-admin/'
        ]
        
        for directory in directories:
            response = self.make_request(directory)
            if response and response.status_code == 200:
                if 'Index of' in response.text:
                    print(f"  ✅ {directory} - Directory listing activé")
                else:
                    print(f"  ℹ️  {directory} - Accessible")
            elif response and response.status_code == 403:
                print(f"  ⚠️  {directory} - Existe mais protégé")
    
    def enumerate_themes(self):
        """Énumère les thèmes WordPress"""
        print("\n🔍 Énumération des thèmes")
        print("-" * 40)
        
        # Thèmes populaires à tester
        common_themes = [
            'twentytwentyfour', 'twentytwentythree', 'twentytwentytwo',
            'twentytwentyone', 'twentytwenty', 'twentynineteen',
            'astra', 'oceanwp', 'generatepress', 'neve'
        ]
        
        themes_found = []
        
        for theme in common_themes:
            theme_url = f'/wp-content/themes/{theme}/'
            response = self.make_request(theme_url)
            
            if response and response.status_code == 200:
                themes_found.append(theme)
                print(f"  ✅ {theme}")
                
                # Tenter de détecter la version
                version_file = f'/wp-content/themes/{theme}/style.css'
                version_resp = self.make_request(version_file)
                if version_resp and version_resp.status_code == 200:
                    version_match = re.search(r'Version:\s*([0-9.]+)', version_resp.text)
                    if version_match:
                        print(f"     Version: {version_match.group(1)}")
        
        if not themes_found:
            print("  ❌ Aucun thème commun détecté")
    
    def enumerate_plugins(self):
        """Énumère les plugins WordPress"""
        print("\n🔍 Énumération des plugins")
        print("-" * 40)
        
        # Plugins populaires à tester
        common_plugins = [
            'akismet', 'jetpack', 'yoast', 'contact-form-7',
            'woocommerce', 'elementor', 'wordfence', 'wpforms',
            'all-in-one-wp-migration', 'updraftplus', 'wp-super-cache'
        ]
        
        plugins_found = []
        
        for plugin in common_plugins:
            plugin_url = f'/wp-content/plugins/{plugin}/'
            response = self.make_request(plugin_url)
            
            if response and response.status_code == 200:
                plugins_found.append(plugin)
                print(f"  ✅ {plugin}")
                
                # Tenter de détecter la version
                readme_file = f'/wp-content/plugins/{plugin}/readme.txt'
                readme_resp = self.make_request(readme_file)
                if readme_resp and readme_resp.status_code == 200:
                    version_match = re.search(r'Stable tag:\s*([0-9.]+)', readme_resp.text)
                    if version_match:
                        print(f"     Version: {version_match.group(1)}")
        
        if not plugins_found:
            print("  ❌ Aucun plugin commun détecté")
    
    def run_full_scan(self):
        """Lance un scan complet"""
        self.print_banner()
        
        try:
            self.scan_headers()
            self.detect_wordpress_version()
            self.scan_users()
            self.scan_common_files()
            self.scan_wp_content()
            self.enumerate_themes()
            self.enumerate_plugins()
            
            print("\n" + "=" * 60)
            print("✅ Scan terminé")
            print("=" * 60)
            
        except KeyboardInterrupt:
            print("\n❌ Scan interrompu par l'utilisateur")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description='WordPress Security Scanner - Pour tests autorisés uniquement'
    )
    parser.add_argument('url', help='URL du site WordPress à scanner')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Timeout pour les requêtes (défaut: 10s)')
    
    args = parser.parse_args()
    
    # Validation de l'URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'http://' + args.url
    
    # Avertissement légal
    print("⚠️  AVERTISSEMENT: Ce script est destiné uniquement aux tests")
    print("   de sécurité autorisés sur vos propres systèmes.")
    print("   L'utilisation non autorisée peut être illégale.")
    print()
    
    scanner = WordPressScanner(args.url, args.timeout)
    scanner.run_full_scan()

if __name__ == '__main__':
    main()
