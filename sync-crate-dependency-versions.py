#!/usr/bin/env python3
"""
Script to detect dependency version differences between local sdk crates and upstream repository.
Based on sync-crate-versions.py but focuses on dependency versions instead of crate versions.
"""

import argparse
import os
import re
import requests
import sys
import time
from pathlib import Path
import toml

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

def parse_dependencies(cargo_toml_content):
    """Parse dependencies from Cargo.toml content."""
    if not cargo_toml_content:
        return {}
    
    try:
        parsed = toml.loads(cargo_toml_content)
        dependencies = {}
        
        # Get regular dependencies
        if 'dependencies' in parsed:
            for dep_name, dep_info in parsed['dependencies'].items():
                if isinstance(dep_info, dict):
                    if 'version' in dep_info:
                        dependencies[dep_name] = dep_info['version']
                elif isinstance(dep_info, str):
                    dependencies[dep_name] = dep_info
        
        # Get dev dependencies
        if 'dev-dependencies' in parsed:
            for dep_name, dep_info in parsed['dev-dependencies'].items():
                if isinstance(dep_info, dict):
                    if 'version' in dep_info:
                        dependencies[f"dev:{dep_name}"] = dep_info['version']
                elif isinstance(dep_info, str):
                    dependencies[f"dev:{dep_name}"] = dep_info
        
        # Get build dependencies
        if 'build-dependencies' in parsed:
            for dep_name, dep_info in parsed['build-dependencies'].items():
                if isinstance(dep_info, dict):
                    if 'version' in dep_info:
                        dependencies[f"build:{dep_name}"] = dep_info['version']
                elif isinstance(dep_info, str):
                    dependencies[f"build:{dep_name}"] = dep_info
        
        return dependencies
    except toml.TomlDecodeError as e:
        print(f"Error parsing TOML: {e}")
        return {}

def compare_dependencies(local_deps, remote_deps):
    """Compare local and remote dependencies and return differences."""
    differences = []
    
    # Check for version differences in common dependencies
    for dep_name in local_deps:
        if dep_name in remote_deps:
            local_version = local_deps[dep_name]
            remote_version = remote_deps[dep_name]
            if local_version != remote_version:
                differences.append({
                    'type': 'version_diff',
                    'dependency': dep_name,
                    'local_version': local_version,
                    'remote_version': remote_version
                })
    
    # Check for dependencies only in local (should not be removed)
    for dep_name in local_deps:
        if dep_name not in remote_deps:
            differences.append({
                'type': 'local_only',
                'dependency': dep_name,
                'local_version': local_deps[dep_name]
            })
    
    # Check for dependencies only in remote
    for dep_name in remote_deps:
        if dep_name not in local_deps:
            differences.append({
                'type': 'remote_only',
                'dependency': dep_name,
                'remote_version': remote_deps[dep_name]
            })
    
    return differences

def update_dependency_version(cargo_toml_path, dep_name, new_version, dry_run=False):
    """Update a specific dependency version in Cargo.toml while preserving table format."""
    with open(cargo_toml_path, 'r') as f:
        content = f.read()
    
    # Parse the dependency type from the name
    dep_type = 'dependencies'
    actual_dep_name = dep_name
    
    if dep_name.startswith('dev:'):
        dep_type = 'dev-dependencies'
        actual_dep_name = dep_name[4:]
    elif dep_name.startswith('build:'):
        dep_type = 'build-dependencies'
        actual_dep_name = dep_name[6:]
    
    lines = content.split('\n')
    updated_lines = []
    old_version = None
    in_dep_table = False
    current_dep_name = None
    
    for line in lines:
        stripped = line.strip()
        
        # Check if we're entering a dependency table
        if stripped.startswith(f'[{dep_type}.') and stripped.endswith(']'):
            # Extract dependency name from table header
            table_match = re.match(rf'^\[{re.escape(dep_type)}\.([^]]+)\]$', stripped)
            if table_match:
                current_dep_name = table_match.group(1).strip('\"')
                in_dep_table = (current_dep_name == actual_dep_name)
            updated_lines.append(line)
            continue
        
        # Check if we're leaving a table section
        if stripped.startswith('[') and stripped.endswith(']'):
            in_dep_table = False
            current_dep_name = None
            updated_lines.append(line)
            continue
        
        # If we're in the target dependency table, look for version
        if in_dep_table and stripped.startswith('version ='):
            version_match = re.search(r'version = "([^"]+)"', line)
            if version_match:
                old_version = version_match.group(1)
                if not dry_run:
                    updated_line = re.sub(r'version = "([^"]+)"', f'version = "{new_version}"', line)
                    updated_lines.append(updated_line)
                else:
                    updated_lines.append(line)
                continue
        
        updated_lines.append(line)
    
    # Write back to file if not dry run and we found the dependency
    if not dry_run and old_version:
        with open(cargo_toml_path, 'w') as f:
            f.write('\n'.join(updated_lines))
    
    return old_version

def add_missing_dependency(cargo_toml_path, dep_name, version, dry_run=False):
    """Add a missing dependency to Cargo.toml."""
    with open(cargo_toml_path, 'r') as f:
        content = f.read()
    
    # Parse the dependency type from the name
    dep_type = 'dependencies'
    actual_dep_name = dep_name
    
    if dep_name.startswith('dev:'):
        dep_type = 'dev-dependencies'
        actual_dep_name = dep_name[4:]
    elif dep_name.startswith('build:'):
        dep_type = 'build-dependencies'
        actual_dep_name = dep_name[6:]
    
    try:
        parsed = toml.loads(content)
        
        # Ensure the dependency section exists
        if dep_type not in parsed:
            parsed[dep_type] = {}
        
        # Add the dependency
        if not dry_run:
            parsed[dep_type][actual_dep_name] = version
        
        # Write back to file if not dry run
        if not dry_run:
            with open(cargo_toml_path, 'w') as f:
                toml.dump(parsed, f)
        
        return True
    except toml.TomlDecodeError as e:
        raise Exception(f"Error parsing TOML: {e}")

def main():
    parser = argparse.ArgumentParser(description='Detect and optionally update dependency version differences between local and upstream repository')
    parser.add_argument('--upstream-repo', default='awslabs/aws-sdk-rust', help='Upstream repository (default: awslabs/aws-sdk-rust)')
    parser.add_argument('--commit-hash', default='main', help='The commit hash or branch to compare against (default: main)')
    parser.add_argument('--limit', type=int, default=None, help='Limit number of crates to process (for testing)')
    parser.add_argument('--crate', help='Process only a specific crate')
    parser.add_argument('--update', action='store_true', help='Update local Cargo.toml files with upstream versions')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be updated without making changes')
    parser.add_argument('--add-missing', action='store_true', help='Add missing dependencies from upstream')
    args = parser.parse_args()
    
    # Validate arguments
    if args.dry_run and not args.update:
        print('Error: --dry-run can only be used with --update')
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
    
    if args.crate:
        crate_dirs = [d for d in crate_dirs if d.name == args.crate]
        if not crate_dirs:
            print(f"Error: crate '{args.crate}' not found")
            sys.exit(1)
    
    if args.limit:
        crate_dirs = crate_dirs[:args.limit]
    
    total_differences = []
    errors = []
    
    print(f"Processing {len(crate_dirs)} crates...")
    print(f"Comparing against upstream: {args.upstream_repo} @ {args.commit_hash}")
    
    for i, crate_dir in enumerate(crate_dirs, 1):
        crate_name = crate_dir.name
        cargo_toml_path = crate_dir / 'Cargo.toml'
        
        print(f"\n[{i}/{len(crate_dirs)}] Processing {crate_name}...")
        
        try:
            # Get local dependencies
            with open(cargo_toml_path, 'r') as f:
                local_content = f.read()
            local_deps = parse_dependencies(local_content)
            
            # Get remote dependencies
            remote_content = fetch_remote_cargo_toml(args.upstream_repo, args.commit_hash, crate_name, headers)
            if not remote_content:
                print(f"  Warning: Could not fetch remote Cargo.toml for {crate_name} (crate may not exist in upstream)")
                continue
            
            remote_deps = parse_dependencies(remote_content)
            
            # Compare dependencies
            differences = compare_dependencies(local_deps, remote_deps)
            
            if differences:
                print(f"  Found {len(differences)} dependency differences:")
                
                updates_made = []
                
                for diff in differences:
                    if diff['type'] == 'version_diff':
                        print(f"    • {diff['dependency']}: {diff['local_version']} → {diff['remote_version']}")
                        
                        if args.update:
                            try:
                                old_version = update_dependency_version(
                                    cargo_toml_path, 
                                    diff['dependency'], 
                                    diff['remote_version'], 
                                    dry_run=args.dry_run
                                )
                                if old_version:
                                    action = "Would update" if args.dry_run else "Updated"
                                    print(f"      {action}: {diff['dependency']} {old_version} → {diff['remote_version']}")
                                    updates_made.append(diff)
                            except Exception as e:
                                print(f"      Error updating {diff['dependency']}: {e}")
                    
                    elif diff['type'] == 'local_only':
                        print(f"    • {diff['dependency']}: {diff['local_version']} (local only - preserved)")
                    
                    elif diff['type'] == 'remote_only':
                        print(f"    • {diff['dependency']}: {diff['remote_version']} (missing locally)")
                        
                        if args.update and args.add_missing:
                            try:
                                success = add_missing_dependency(
                                    cargo_toml_path, 
                                    diff['dependency'], 
                                    diff['remote_version'], 
                                    dry_run=args.dry_run
                                )
                                if success:
                                    action = "Would add" if args.dry_run else "Added"
                                    print(f"      {action}: {diff['dependency']} {diff['remote_version']}")
                                    updates_made.append(diff)
                            except Exception as e:
                                print(f"      Error adding {diff['dependency']}: {e}")
                
                if updates_made and not args.dry_run:
                    print(f"  Applied {len(updates_made)} updates to {crate_name}")
                elif updates_made and args.dry_run:
                    print(f"  Would apply {len(updates_made)} updates to {crate_name}")
                
                total_differences.extend([{'crate': crate_name, **diff} for diff in differences])
            else:
                print(f"  No dependency differences found")
            
        except Exception as e:
            error_msg = f"Error processing {crate_name}: {str(e)}"
            errors.append(error_msg)
            print(f"  Error: {str(e)}")
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"SUMMARY")
    print(f"{'='*60}")
    print(f"Processed {len(crate_dirs)} crates")
    print(f"Found {len(total_differences)} total dependency differences")
    
    if total_differences:
        print(f"\nDependency differences by type:")
        version_diffs = [d for d in total_differences if d['type'] == 'version_diff']
        local_only = [d for d in total_differences if d['type'] == 'local_only']
        remote_only = [d for d in total_differences if d['type'] == 'remote_only']
        
        print(f"  Version differences: {len(version_diffs)}")
        print(f"  Local-only dependencies: {len(local_only)}")
        print(f"  Missing dependencies: {len(remote_only)}")
        
        if version_diffs:
            print(f"\nVersion differences:")
            for diff in version_diffs:
                print(f"  {diff['crate']}: {diff['dependency']} {diff['local_version']} → {diff['remote_version']}")
        
        if local_only:
            print(f"\nLocal-only dependencies (preserved):")
            for diff in local_only:
                print(f"  {diff['crate']}: {diff['dependency']} {diff['local_version']}")
        
        if remote_only:
            print(f"\nMissing dependencies:")
            for diff in remote_only:
                print(f"  {diff['crate']}: {diff['dependency']} {diff['remote_version']}")
    
    if errors:
        print(f"\nErrors:")
        for error in errors:
            print(f"  {error}")
    
    if errors:
        sys.exit(1)

if __name__ == "__main__":
    main()