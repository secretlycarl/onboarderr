#!/usr/bin/env python3
"""
Port Configuration Script for Onboarderr

This script allows you to change the application port in one place
and automatically updates all necessary files.

Usage:
    python changeport.py [new_port]

Examples:
    python changeport.py 8080
    python changeport.py 9000
"""

import os
import sys
import re
import shutil
from datetime import datetime

def backup_files():
    """Create backups of files that will be modified"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    files_to_backup = ['compose.yml', 'Dockerfile']
    
    backup_dir = f"backup_{timestamp}"
    os.makedirs(backup_dir, exist_ok=True)
    
    for file in files_to_backup:
        if os.path.exists(file):
            shutil.copy2(file, os.path.join(backup_dir, file))
            print(f"Backed up {file} to {backup_dir}/")
    
    return backup_dir



def update_compose_yml(new_port):
    """Update compose.yml port mapping"""
    with open('compose.yml', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace the port mapping
    pattern = r'ports:\s*\n\s*- "\d+:\d+"'
    replacement = f'ports:\n      - "{new_port}:{new_port}"'
    
    if re.search(pattern, content):
        content = re.sub(pattern, replacement, content)
        with open('compose.yml', 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✓ Updated compose.yml port mapping to {new_port}:{new_port}")
    else:
        print("⚠ Could not find port mapping in compose.yml")

def update_dockerfile(new_port):
    """Update Dockerfile EXPOSE directive"""
    with open('Dockerfile', 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace the EXPOSE line
    pattern = r'EXPOSE \d+'
    replacement = f'EXPOSE {new_port}'
    
    if re.search(pattern, content):
        content = re.sub(pattern, replacement, content)
        with open('Dockerfile', 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"✓ Updated Dockerfile EXPOSE directive to {new_port}")
    else:
        print("⚠ Could not find EXPOSE line in Dockerfile")

def update_env_file(new_port):
    """Add or update APP_PORT in .env file"""
    env_file = '.env'
    
    # Read existing .env file
    if os.path.exists(env_file):
        with open(env_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    else:
        lines = []
    
    # Check if APP_PORT already exists
    app_port_exists = False
    for i, line in enumerate(lines):
        if line.strip().startswith('APP_PORT='):
            lines[i] = f'APP_PORT={new_port}\n'
            app_port_exists = True
            break
    
    # Add APP_PORT if it doesn't exist
    if not app_port_exists:
        lines.append(f'APP_PORT={new_port}\n')
    
    # Write back to .env file
    with open(env_file, 'w', encoding='utf-8') as f:
        f.writelines(lines)
    
    print(f"✓ Updated {env_file} with APP_PORT={new_port}")

def validate_port(port_str):
    """Validate that the port is a valid number"""
    try:
        port = int(port_str)
        if 1 <= port <= 65535:
            return port
        else:
            print("❌ Error: Port must be between 1 and 65535")
            return None
    except ValueError:
        print("❌ Error: Port must be a valid number")
        return None

def main():
    if len(sys.argv) != 2:
        print(__doc__)
        print("\nCurrent configuration:")
        print("  - app.py: Uses APP_PORT environment variable (no update needed)")
        print("  - compose.yml: Maps port 10000:10000")
        print("  - Dockerfile: EXPOSE 10000")
        print("\nTo change the port, run:")
        print("  python changeport.py [new_port]")
        sys.exit(1)
    
    new_port = validate_port(sys.argv[1])
    if new_port is None:
        sys.exit(1)
    
    print(f"🔄 Changing port to {new_port}...")
    print()
    
    # Create backups
    backup_dir = backup_files()
    print()
    
    # Update files
    update_compose_yml(new_port)
    update_dockerfile(new_port)
    update_env_file(new_port)
    
    print()
    print("✅ Port configuration updated successfully!")
    print()
    print("Next steps:")
    print(f"  1. The app will now use port {new_port} by default")
    print(f"  2. You can override this by setting APP_PORT in your .env file")
    print("  3. If using Docker Compose, restart your containers:")
    print("     docker-compose down && docker-compose up -d")
    print("  4. If using Docker directly, rebuild your image:")
    print("     docker build -t onboarderr .")
    print()
    print(f"Backup files are available in: {backup_dir}/")

if __name__ == "__main__":
    main() 