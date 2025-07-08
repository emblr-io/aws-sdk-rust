#!/usr/bin/env python3
"""
Script to revert crate versions in the sdk directory to match a specific commit from GitHub.
"""

import argparse
import os
import re
import requests
import sys
import time
from pathlib import Path

def get_remote_repo():
    """Get the remote repository URL from git config."""
    import subprocess
    try:
        result = subprocess.run(['git', 'remote', 'get-url', 'origin'], 
                              capture_output=True, text=True, check=True)
        remote_url = result.stdout.strip()
        
        # Convert SSH URL to HTTPS format for API access
        if remote_url.startswith('git@github.com:'):
            remote_url = remote_url.replace('git@github.com:', 'https://github.com/')
        if remote_url.endswith('.git'):
            remote_url = remote_url[:-4]
        
        # Extract owner/repo from URL
        parts = remote_url.split('/')
        if len(parts) >= 2:
            owner = parts[-2]
            repo = parts[-1]
            return f"{owner}/{repo}"
        else:
            raise ValueError("Could not parse repository from remote URL")
    except subprocess.CalledProcessError:
        raise ValueError("Could not get remote repository URL")

def get_auth_info():
    """Get authentication info for GitHub API using gh CLI."""
    import subprocess
    try:
        # Get the token
        token_result = subprocess.run(['gh', 'auth', 'token'], 
                                    capture_output=True, text=True, check=True)
        token = token_result.stdout.strip()
        
        # Get the authenticated user
        user_result = subprocess.run(['gh', 'auth', 'status'], 
                                   capture_output=True, text=True, check=True)
        # Parse the user from the status output
        user = None
        for line in user_result.stdout.split('\n'):
            if 'Logged in to github.com account' in line:
                # Extract username from "  ✓ Logged in to github.com account username (keyring)"
                user = line.split('account ')[1].split(' ')[0]
                break
        
        return {'Authorization': f'token {token}'}, user
    except subprocess.CalledProcessError:
        print("Warning: Could not get GitHub token from 'gh auth token'. API rate limits may apply.")
        return {}, None
    except FileNotFoundError:
        print("Warning: 'gh' CLI not found. API rate limits may apply.")
        return {}, None

class RateLimiter:
    """Rate limiter for GitHub API requests."""
    
    def __init__(self):
        # GitHub API limits: 5000 requests/hour, 900 points/minute
        # Contents endpoint is typically 1 point per request
        # To be safe, let's limit to 800 requests per minute (leaving buffer)
        # This translates to ~13.3 requests per second, so we'll use 0.075 second delay
        self.delay = 0.075  # 75ms between requests
        self.last_request_time = 0
    
    def wait_if_needed(self):
        """Wait if necessary to respect rate limits."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.delay:
            sleep_time = self.delay - time_since_last
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

# Global rate limiter instance
rate_limiter = RateLimiter()

def fetch_remote_cargo_toml(repo, commit_hash, crate_path, headers):
    """Fetch Cargo.toml content from GitHub for a specific commit."""
    import base64
    
    # Apply rate limiting
    rate_limiter.wait_if_needed()
    
    url = f"https://api.github.com/repos/{repo}/contents/sdk/{crate_path}/Cargo.toml"
    params = {'ref': commit_hash}
    
    response = requests.get(url, params=params, headers=headers)
    
    # Check rate limit headers and warn if we're getting close
    if 'X-RateLimit-Remaining' in response.headers:
        remaining = int(response.headers['X-RateLimit-Remaining'])
        if remaining < 100:
            print(f"  Warning: Only {remaining} API requests remaining")
    
    if response.status_code == 404:
        return None
    elif response.status_code == 403:
        # Check if it's a rate limit issue
        if 'X-RateLimit-Remaining' in response.headers:
            remaining = int(response.headers['X-RateLimit-Remaining'])
            if remaining == 0:
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                current_time = int(time.time())
                wait_time = reset_time - current_time
                raise Exception(f"Rate limit exceeded. Try again in {wait_time} seconds.")
        raise Exception(f"Failed to fetch {crate_path}/Cargo.toml: 403 Forbidden")
    elif response.status_code != 200:
        raise Exception(f"Failed to fetch {crate_path}/Cargo.toml: {response.status_code}")
    
    content = base64.b64decode(response.json()['content']).decode('utf-8')
    return content

def extract_version(cargo_toml_content):
    """Extract version from Cargo.toml content."""
    if not cargo_toml_content:
        return None
    
    # Look for version line in [package] section
    lines = cargo_toml_content.split('\n')
    in_package_section = False
    
    for line in lines:
        stripped = line.strip()
        if stripped == '[package]':
            in_package_section = True
            continue
        elif stripped.startswith('[') and stripped != '[package]':
            in_package_section = False
            continue
        
        if in_package_section and stripped.startswith('version = '):
            # Extract version string
            match = re.search(r'version = "([^"]+)"', stripped)
            if match:
                return match.group(1)
    
    return None

def update_local_version(cargo_toml_path, new_version):
    """Update version in local Cargo.toml file."""
    with open(cargo_toml_path, 'r') as f:
        content = f.read()
    
    # Find and replace the version line in [package] section
    lines = content.split('\n')
    in_package_section = False
    updated_lines = []
    
    for line in lines:
        stripped = line.strip()
        if stripped == '[package]':
            in_package_section = True
            updated_lines.append(line)
            continue
        elif stripped.startswith('[') and stripped != '[package]':
            in_package_section = False
            updated_lines.append(line)
            continue
        
        if in_package_section and stripped.startswith('version = '):
            # Replace version
            updated_line = re.sub(r'version = "[^"]+"', f'version = "{new_version}"', line)
            updated_lines.append(updated_line)
        else:
            updated_lines.append(line)
    
    with open(cargo_toml_path, 'w') as f:
        f.write('\n'.join(updated_lines))

def main():
    parser = argparse.ArgumentParser(description='Revert crate versions to match a specific commit')
    parser.add_argument('commit_hash', help='The commit hash to revert versions to')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of crates to process (for testing)')
    args = parser.parse_args()
    
    # Get the remote repository
    try:
        repo = get_remote_repo()
        print(f"Using repository: {repo}")
    except Exception as e:
        print(f"Error getting remote repository: {e}")
        sys.exit(1)
    
    # Get authentication info
    headers, user = get_auth_info()
    if user:
        print(f"Authenticated as: {user}")
    else:
        print("No authentication - using anonymous requests")
    
    # Find all crate directories in sdk/
    sdk_path = Path('sdk')
    if not sdk_path.exists():
        print("Error: sdk directory not found")
        sys.exit(1)
    
    crate_dirs = [d for d in sdk_path.iterdir() if d.is_dir() and (d / 'Cargo.toml').exists()]
    
    if args.limit:
        crate_dirs = crate_dirs[:args.limit]
    
    changes = []
    errors = []
    
    print(f"Processing {len(crate_dirs)} crates...")
    
    for i, crate_dir in enumerate(crate_dirs, 1):
        crate_name = crate_dir.name
        cargo_toml_path = crate_dir / 'Cargo.toml'
        
        print(f"[{i}/{len(crate_dirs)}] Processing {crate_name}...")
        
        try:
            # Get current version
            with open(cargo_toml_path, 'r') as f:
                current_content = f.read()
            current_version = extract_version(current_content)
            
            if not current_version:
                errors.append(f"Could not extract current version from {crate_name}")
                continue
            
            # Get remote version
            remote_content = fetch_remote_cargo_toml(repo, args.commit_hash, crate_name, headers)
            if not remote_content:
                errors.append(f"Could not fetch remote Cargo.toml for {crate_name}")
                continue
            
            remote_version = extract_version(remote_content)
            if not remote_version:
                errors.append(f"Could not extract remote version from {crate_name}")
                continue
            
            # Update if versions differ
            if current_version != remote_version:
                update_local_version(cargo_toml_path, remote_version)
                changes.append(f"{crate_name}: {current_version} -> {remote_version}")
                print(f"  Updated: {current_version} -> {remote_version}")
            else:
                print(f"  No change needed: {current_version}")
            
        except Exception as e:
            errors.append(f"Error processing {crate_name}: {str(e)}")
            print(f"  Error: {str(e)}")
    
    # Print results
    print(f"\nProcessed {len(crate_dirs)} crates")
    print(f"Updated {len(changes)} crates")
    
    if changes:
        print("\nVersion changes:")
        for change in changes:
            print(f"  {change}")
    
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  {error}")
    
    if errors:
        sys.exit(1)

if __name__ == "__main__":
    main()