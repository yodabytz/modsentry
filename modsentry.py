#!/usr/bin/env python3

import re
import time
import curses
import os
import subprocess
import sys
import whois
import select
import json
import glob
import argparse
import socket
from datetime import datetime

# Version
VERSION = "1.5"

# Configuration file paths
CONFIG_FILE = "/etc/modsentry/modsentry.conf"
IGNORE_RULES_FILE = "/etc/modsentry/ignore-rules.conf"

# Default configuration (will be overridden by config file)
LOG_FILE_PATH = "/var/log/modsec_audit.log"
AUDIT_LOG_PATH = "/var/log/modsentry-audit.log"
BLOCKED_IPS_FILE = "/etc/modsentry/blocked-ips.conf"
WHITELIST_FILE = "/etc/modsentry/whitelist.conf"
IGNORE_RULE_IDS = set()  # Will be loaded from config
MIN_WIDTH = 128
MIN_HEIGHT = 24
MAX_ENTRIES = 200
THEME_DIR = "/etc/modsentry/themes"
DEFAULT_THEME = "default"

# Mapping of severity numbers to descriptions
SEVERITY_MAP = {
    "0": "Emergency",
    "1": "Alert",
    "2": "Critical",
    "3": "Error",
    "4": "Warning",
    "5": "Notice",
    "6": "Info",
    "7": "Debug"
}

# Global variables for theme management
current_theme = None
theme_colors = {}

# Mapping of severity descriptions to color names
SEVERITY_COLOR_MAP = {
    "Emergency": "severity_emergency",
    "Alert": "severity_alert",
    "Critical": "severity_critical",
    "Error": "severity_error",
    "Warning": "severity_warning",
    "Notice": "severity_notice",
    "Info": "severity_info",
    "Debug": "severity_debug"
}

def load_config():
    """Load configuration from config file."""
    global LOG_FILE_PATH, AUDIT_LOG_PATH, BLOCKED_IPS_FILE, WHITELIST_FILE
    global MIN_WIDTH, MIN_HEIGHT, MAX_ENTRIES, THEME_DIR, DEFAULT_THEME, IGNORE_RULE_IDS

    if not os.path.exists(CONFIG_FILE):
        return  # Use defaults if no config file

    try:
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if '=' not in line:
                    continue

                key, value = line.split('=', 1)
                key = key.strip()
                value = value.strip()

                if key == 'log_file':
                    LOG_FILE_PATH = value
                elif key == 'audit_log':
                    AUDIT_LOG_PATH = value
                elif key == 'blocked_ips_file':
                    BLOCKED_IPS_FILE = value
                elif key == 'whitelist_file':
                    WHITELIST_FILE = value
                elif key == 'min_width':
                    MIN_WIDTH = int(value)
                elif key == 'min_height':
                    MIN_HEIGHT = int(value)
                elif key == 'max_entries':
                    MAX_ENTRIES = int(value)
                elif key == 'theme_dir':
                    THEME_DIR = value
                elif key == 'default_theme':
                    DEFAULT_THEME = value
    except Exception as e:
        pass  # Use defaults on error

def load_ignore_rules():
    """Load ignore rules from ignore rules file."""
    global IGNORE_RULE_IDS

    IGNORE_RULE_IDS = set()
    if not os.path.exists(IGNORE_RULES_FILE):
        return

    try:
        with open(IGNORE_RULES_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    IGNORE_RULE_IDS.add(line)
    except Exception:
        pass

def add_ignore_rule(rule_id):
    """Add a rule ID to the ignore list and save to file."""
    global IGNORE_RULE_IDS

    rule_id = rule_id.strip()
    if not rule_id or rule_id in IGNORE_RULE_IDS:
        return False  # Already exists or invalid

    IGNORE_RULE_IDS.add(rule_id)

    try:
        with open(IGNORE_RULES_FILE, 'a') as f:
            f.write(f"{rule_id}\n")
        return True
    except Exception:
        # Remove from set if we can't save to file
        IGNORE_RULE_IDS.discard(rule_id)
        return False

def log_audit_action(action, ip_address, rule_id, attack_name, status, details=""):
    """Log an action to the audit trail."""
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        username = os.getenv("SUDO_USER") or os.getenv("USER") or "root"

        # Format: timestamp | username | action | ip | rule_id | attack_name | status | details
        audit_entry = f"{timestamp} | {username} | {action} | {ip_address.strip()} | {rule_id} | {attack_name} | {status}"
        if details:
            audit_entry += f" | {details}"
        audit_entry += "\n"

        # Write to audit log (create if doesn't exist)
        with open(AUDIT_LOG_PATH, "a") as f:
            f.write(audit_entry)
    except Exception as e:
        # Silently fail if we can't write to audit log
        pass

def save_blocked_ip_to_file(ip):
    """Save a blocked IP to the persistent file."""
    try:
        ip = ip.strip()
        # Ensure directory exists
        os.makedirs(os.path.dirname(BLOCKED_IPS_FILE), exist_ok=True)

        # Check if IP already in file
        if os.path.exists(BLOCKED_IPS_FILE):
            with open(BLOCKED_IPS_FILE, 'r') as f:
                existing = f.read()
                if ip in existing:
                    return  # Already saved

        # Append IP to file
        with open(BLOCKED_IPS_FILE, 'a') as f:
            f.write(f"{ip}\n")
    except Exception as e:
        pass  # Silently fail

def remove_blocked_ip_from_file(ip):
    """Remove a blocked IP from the persistent file."""
    try:
        ip = ip.strip()
        if not os.path.exists(BLOCKED_IPS_FILE):
            return

        with open(BLOCKED_IPS_FILE, 'r') as f:
            lines = f.readlines()

        with open(BLOCKED_IPS_FILE, 'w') as f:
            for line in lines:
                if line.strip() != ip:
                    f.write(line)
    except Exception as e:
        pass  # Silently fail

def restore_blocked_ips_from_file():
    """Restore blocked IPs from persistent file to iptables."""
    try:
        if not os.path.exists(BLOCKED_IPS_FILE):
            return

        with open(BLOCKED_IPS_FILE, 'r') as f:
            for line in f:
                ip = line.strip()
                if ip and not line.startswith('#'):
                    # Check if already in iptables
                    if not is_ip_blocked(ip):
                        try:
                            subprocess.run(['iptables', '-A', 'ModSentry', '-s', ip, '-j', 'DROP'],
                                         check=True, timeout=5)
                        except Exception:
                            pass  # Skip IPs that fail to add
    except Exception:
        pass  # Silently fail

def load_whitelist():
    """Load whitelist of trusted IPs from config file."""
    whitelist = set()
    if not os.path.exists(WHITELIST_FILE):
        return whitelist

    try:
        with open(WHITELIST_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    whitelist.add(line)
    except Exception:
        pass

    return whitelist

def hex_to_rgb(hex_color):
    """Convert hex color to RGB tuple."""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def load_theme(theme_name):
    """Load a theme from the themes directory."""
    global current_theme, theme_colors
    
    theme_file = os.path.join(THEME_DIR, f"{theme_name}.json")
    
    if not os.path.exists(theme_file):
        # Fallback to default theme
        theme_file = os.path.join(THEME_DIR, f"{DEFAULT_THEME}.json")
        if not os.path.exists(theme_file):
            # If no themes exist, use built-in fallback
            theme_colors = {
                "title_attack": (0, 255, 255),
                "date": (0, 255, 0),
                "ip_address": (255, 255, 0),
                "rule_id": (255, 255, 255),
                "response_code": (255, 255, 255),
                "severity_base": (0, 0, 255),
                "host": (255, 255, 0),
                "blocked_indicator": (255, 0, 0),
                "severity_emergency": (255, 0, 0),
                "severity_alert": (255, 0, 0),
                "severity_critical": (255, 0, 0),
                "severity_error": (255, 0, 0),
                "severity_warning": (255, 255, 0),
                "severity_notice": (0, 0, 255),
                "severity_info": (0, 255, 0),
                "severity_debug": (0, 255, 255)
            }
            current_theme = "builtin"
            return
    
    try:
        with open(theme_file, 'r') as f:
            theme_data = json.load(f)
            
        theme_colors = {}
        for color_name, hex_color in theme_data['colors'].items():
            theme_colors[color_name] = hex_to_rgb(hex_color)
            
        current_theme = theme_data['name']
    except (json.JSONDecodeError, KeyError, IOError) as e:
        # Fallback to built-in colors on error
        load_theme(DEFAULT_THEME)

def get_available_themes():
    """Get list of available theme names."""
    if not os.path.exists(THEME_DIR):
        return []
    
    theme_files = glob.glob(os.path.join(THEME_DIR, "*.json"))
    return [os.path.splitext(os.path.basename(f))[0] for f in theme_files]

def get_color_pair_for_severity(severity_color_name):
    """Get the color pair number for a severity color name."""
    color_pair_map = {
        "severity_emergency": 9,
        "severity_alert": 10,
        "severity_critical": 11,
        "severity_error": 12,
        "severity_warning": 13,
        "severity_notice": 14,
        "severity_info": 15,
        "severity_debug": 16,
        "severity_base": 6
    }
    return color_pair_map.get(severity_color_name, 6)

def get_response_code_color_pair(response_code, severity):
    """Get color pair for response code based on HTTP status and severity."""
    try:
        code = int(response_code.strip())
        
        # High threat responses (4xx, 5xx) - use severity-based colors
        if code >= 500:  # Server errors - critical
            return get_color_pair_for_severity("severity_critical")
        elif code >= 400:  # Client errors - error/warning based on severity
            if severity.strip() in ["Emergency", "Alert", "Critical", "Error"]:
                return get_color_pair_for_severity("severity_error")
            else:
                return get_color_pair_for_severity("severity_warning")
        elif code >= 300:  # Redirects - notice
            return get_color_pair_for_severity("severity_notice")
        elif code >= 200:  # Success - info
            return get_color_pair_for_severity("severity_info")
        else:  # 1xx - debug
            return get_color_pair_for_severity("severity_debug")
    except (ValueError, AttributeError):
        # If response code is invalid, use severity color
        severity_color_name = SEVERITY_COLOR_MAP.get(severity.strip(), "severity_base")
        return get_color_pair_for_severity(severity_color_name)

def get_theme_from_env():
    """Get theme name from environment variable or use default."""
    return os.environ.get('MODSENTRY_THEME', DEFAULT_THEME)

def truncate_text(text, width, ellipsis='...'):
    """Smart text truncation with ellipsis."""
    if not text:
        return ''
    
    text = str(text).strip()
    if len(text) <= width:
        return text
    
    if width <= len(ellipsis):
        return text[:width]
    
    return text[:width - len(ellipsis)] + ellipsis

def reinitialize_colors_with_theme(theme_name):
    """Reinitialize colors with a new theme without restarting the application."""
    global theme_colors, current_theme
    
    try:
        # Load the new theme
        load_theme(theme_name)
        
        # Check if terminal supports truecolor
        if curses.can_change_color() and curses.COLORS >= 256:
            # Update background color
            bg_color_id = 100
            if "background" in theme_colors:
                bg_r, bg_g, bg_b = theme_colors["background"]
                bg_r_curses = int((bg_r / 255.0) * 1000)
                bg_g_curses = int((bg_g / 255.0) * 1000)
                bg_b_curses = int((bg_b / 255.0) * 1000)
                curses.init_color(bg_color_id, bg_r_curses, bg_g_curses, bg_b_curses)
            else:
                curses.init_color(bg_color_id, 0, 0, 0)
            
            # Map color names to curses color pairs
            color_pair_map = {
                "title_attack": 1,
                "date": 2,
                "ip_address": 3,
                "local_ip_address": 17,  # New color for local IPs
                "rule_id": 4,
                "response_code": 5,
                "severity_base": 6,
                "host": 7,
                "blocked_indicator": 8,
                "severity_emergency": 9,
                "severity_alert": 10,
                "severity_critical": 11,
                "severity_error": 12,
                "severity_warning": 13,
                "severity_notice": 14,
                "severity_info": 15,
                "severity_debug": 16
            }
            
            # Update existing color definitions with background
            color_id = 16  # Start from color 16 to avoid basic colors
            for color_name, pair_id in color_pair_map.items():
                if color_name in theme_colors:
                    r, g, b = theme_colors[color_name]
                    # Convert RGB (0-255) to curses range (0-1000)
                    r_curses = int((r / 255.0) * 1000)
                    g_curses = int((g / 255.0) * 1000)
                    b_curses = int((b / 255.0) * 1000)
                    
                    curses.init_color(color_id, r_curses, g_curses, b_curses)
                    curses.init_pair(pair_id, color_id, bg_color_id)  # Use background color
                    color_id += 1
        
        return current_theme
    except Exception as e:
        # If theme switching fails, keep current theme
        return current_theme if current_theme else "unknown"

def get_whois_info(ip_address):
    """Fetch Whois information for a given IP address and format it."""
    try:
        w = whois.whois(ip_address)
        whois_info = []
        for key, value in w.items():
            if isinstance(value, list):
                value = ", ".join(value)
            whois_info.append(f"{key}: {value}")
        return "\n".join(whois_info)
    except Exception as e:
        # Fallback to running the whois command directly if there's an issue
        try:
            result = subprocess.run(['whois', ip_address], capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as fallback_e:
            return f"Whois lookup failed: {str(fallback_e)}"

def check_iptables_chain():
    """Check if the ModSentry iptables chain exists and create it if not."""
    try:
        # Check if the ModSentry chain exists
        subprocess.run(['iptables', '-L', 'ModSentry'], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Chain exists, restore blocked IPs from persistent file
        restore_blocked_ips_from_file()
    except subprocess.CalledProcessError:
        # Create the ModSentry chain if it doesn't exist
        subprocess.run(['iptables', '-N', 'ModSentry'], check=True)
        # Insert the ModSentry chain at position 1 (checked FIRST, before ACCEPT rules)
        subprocess.run(['iptables', '-I', 'INPUT', '1', '-j', 'ModSentry'], check=True)
        # Restore blocked IPs from persistent file
        restore_blocked_ips_from_file()

def is_ip_blocked(ip):
    """Check if the given IP is already blocked in the ModSentry chain."""
    result = subprocess.run(['iptables', '-L', 'ModSentry', '-n'], capture_output=True, text=True)
    return ip in result.stdout

def block_ip(ip, rule_id="", attack_name=""):
    """Block the given IP address using iptables with audit logging and persistence."""
    try:
        # Trim whitespace from the IP address
        ip = ip.strip()
        if not is_ip_blocked(ip):
            subprocess.run(['iptables', '-A', 'ModSentry', '-s', ip, '-j', 'DROP'], check=True)
            # Save to persistent file
            save_blocked_ip_to_file(ip)
            # Log to audit trail
            log_audit_action("BLOCK", ip, rule_id, attack_name, "Success")
            return f"IP {ip} has been blocked."
        else:
            return f"IP {ip} is already blocked."
    except subprocess.CalledProcessError as e:
        # Log failed block attempt
        log_audit_action("BLOCK", ip, rule_id, attack_name, "Failed", str(e))
        return f"Failed to block IP {ip}: {str(e)}"

def unblock_ip(ip, rule_id="", attack_name=""):
    """Unblock the given IP address using iptables with audit logging and persistence."""
    try:
        # Trim whitespace from the IP address
        ip = ip.strip()
        if is_ip_blocked(ip):
            subprocess.run(['iptables', '-D', 'ModSentry', '-s', ip, '-j', 'DROP'], check=True)
            # Remove from persistent file
            remove_blocked_ip_from_file(ip)
            # Log to audit trail
            log_audit_action("UNBLOCK", ip, rule_id, attack_name, "Success")
            return f"IP {ip} has been unblocked."
        else:
            return f"IP {ip} is not blocked."
    except subprocess.CalledProcessError as e:
        # Log failed unblock attempt
        log_audit_action("UNBLOCK", ip, rule_id, attack_name, "Failed", str(e))
        return f"Failed to unblock IP {ip}: {str(e)}"

def parse_log_entry(entry):
    # Extract the date from section A
    date_match = re.search(r'^---.*?---A--\n\[(.*?)\]', entry, re.MULTILINE)
    remote_date = date_match.group(1) if date_match else 'N/A'

    # Extract the remote IP from section A
    ip_match = re.search(r'^---.*?---A--\n\[.*?\]\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})', entry, re.MULTILINE)
    remote_ip = ip_match.group(1) if ip_match else 'N/A'

    # Extract host from the HTTP Host header (the target server being attacked)
    host_match = re.search(r'^Host:\s*(.+)$', entry, re.MULTILINE)
    if host_match:
        host = host_match.group(1).strip()
        # Remove port if present (e.g., "example.com:8080" -> "example.com")
        if ':' in host:
            host = host.split(':')[0]
    else:
        host = 'N/A'

    # Extract rule ID from section H
    rule_id_match = re.search(r'\[id "(\d+)"\]', entry)
    rule_id = rule_id_match.group(1) if rule_id_match else 'N/A'

    # Extract attack name from section H
    attack_name_match = re.search(r'\[msg "(.*?)"\]', entry)
    attack_name = attack_name_match.group(1) if attack_name_match else 'N/A'

    # Extract severity from section H
    severity_match = re.search(r'\[severity "(\d+)"\]', entry)
    severity = SEVERITY_MAP.get(severity_match.group(1), "N/A") if severity_match else 'N/A'

    # Extract response code from section F
    response_code_match = re.search(r'^---.*?---F--\nHTTP/\d\.\d\s+(\d{3})', entry, re.MULTILINE)
    response_code = response_code_match.group(1) if response_code_match else 'N/A'

    # Extract payload from section B (the request line)
    payload_match = re.search(r'^---.*?---B--\n(.*?)\n', entry, re.MULTILINE)
    payload = payload_match.group(1).strip() if payload_match else 'N/A'

    # Extract info from section H
    info_match = re.search(r'^---.*?---H--\n(.*?)\n---', entry, re.MULTILINE | re.DOTALL)
    info = info_match.group(1).strip() if info_match else 'N/A'

    # Additional info from section E or elsewhere
    additional_info_match = re.search(r'^---.*?---E--\n(.*?)\n---', entry, re.MULTILINE | re.DOTALL)
    additional_info = additional_info_match.group(1).strip() if additional_info_match else 'N/A'

    return remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info

def is_local_ip(ip_str):
    """Check if an IP address is a local/private IP."""
    try:
        parts = ip_str.strip().split('.')
        if len(parts) != 4:
            return False

        octets = [int(p) for p in parts]

        # Check for private IP ranges
        # 10.0.0.0 - 10.255.255.255
        if octets[0] == 10:
            return True
        # 172.16.0.0 - 172.31.255.255
        if octets[0] == 172 and 16 <= octets[1] <= 31:
            return True
        # 192.168.0.0 - 192.168.255.255
        if octets[0] == 192 and octets[1] == 168:
            return True
        # 127.0.0.0 - 127.255.255.255 (localhost)
        if octets[0] == 127:
            return True
        # 169.254.0.0 - 169.254.255.255 (link-local)
        if octets[0] == 169 and octets[1] == 254:
            return True

        return False
    except (ValueError, IndexError):
        return False

def get_domain_from_ip(ip_str):
    """Get domain name from IP using reverse DNS lookup (with caching)."""
    ip_str = ip_str.strip()
    if not ip_str or ip_str == 'N/A':
        return ip_str

    try:
        # Try reverse DNS lookup - timeout after 1 second
        domain = socket.gethostbyaddr(ip_str)[0]
        # Return just the domain, not the full FQDN if it's very long
        if len(domain) > 20:
            return domain.split('.')[-2] + '.' + domain.split('.')[-1]  # Return last two parts
        return domain
    except (socket.herror, socket.timeout, OSError):
        # If reverse DNS fails, return the IP
        return ip_str

def display_log_entries(stdscr, log_entries, current_line, selected_line, blocked_ips, last_draw_state):
    """Display log entries with optimized rendering to reduce flicker."""
    height, width = stdscr.getmaxyx()

    # Calculate positions once
    start_x = max(0, (width - 125) // 2)
    max_width = width - 4

    # Only redraw lines that changed
    for idx, entry in enumerate(log_entries[current_line:current_line + height - 8], start=4):
        # Split the formatted entry into its components
        parts = entry.split('|')
        if len(parts) != 10:
            continue

        date, ip, host, rule_id, attack_name, severity, response_code, _, _, _ = parts

        # Determine if this line is the currently selected one
        entry_idx = current_line + (idx - 4)
        is_selected = (entry_idx == selected_line) and (0 <= entry_idx < len(log_entries))

        # Determine if the IP is blocked
        is_blocked = ip.strip() in blocked_ips

        # Check if this line needs redraw (optimization)
        # Note: Always redraw when selection state changes to prevent highlight bugs
        cache_key = f"{entry_idx}:{entry}"
        if cache_key in last_draw_state:
            continue  # Skip redraw if entry content hasn't changed

        # Clear only the line we're about to update
        stdscr.move(idx, 1)
        stdscr.clrtoeol()

        # Add a red dot for blocked IPs
        if is_blocked:
            stdscr.addstr(idx, start_x - 2, '●', curses.color_pair(8))

        # Display the log entry with colors
        stdscr.addnstr(idx, start_x, date.strip(), 22, curses.color_pair(2) | (curses.A_REVERSE if is_selected else 0))

        # Use different color pair for local vs remote IPs
        ip_color_pair = 17 if is_local_ip(ip) else 3  # 17 for local, 3 for remote
        # Try to show domain name instead of IP, fallback to IP if reverse DNS fails
        display_ip = get_domain_from_ip(ip.strip())
        stdscr.addnstr(idx, start_x + 23, display_ip, 16, curses.color_pair(ip_color_pair) | (curses.A_REVERSE if is_selected else 0))

        stdscr.addnstr(idx, start_x + 40, host.strip(), 20, curses.color_pair(7) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 60, rule_id.strip(), 8, curses.color_pair(4) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 69, attack_name.strip(), 37, curses.color_pair(1) | (curses.A_REVERSE if is_selected else 0))

        # Apply appropriate color to the severity
        severity_color_name = SEVERITY_COLOR_MAP.get(severity.strip(), "severity_info")
        severity_color_pair = get_color_pair_for_severity(severity_color_name)
        severity_pos = start_x + 107
        response_pos = start_x + 117

        if severity_pos + 9 <= max_width:
            stdscr.addnstr(idx, severity_pos, severity.strip().center(9), 9, curses.color_pair(severity_color_pair) | (curses.A_REVERSE if is_selected else 0))

        if response_pos + 8 <= max_width:
            stdscr.addnstr(idx, response_pos, response_code.strip().center(8), 8, curses.color_pair(5) | (curses.A_REVERSE if is_selected else 0))

        # Update cache
        last_draw_state[cache_key] = entry

    # Add the block IP message at the bottom
    footer_text = "Enter: More Info | 'b': Block IP | 'd': Unblock IP | 'i': Ignore Rule | 't': Theme | 'q': Quit | "
    stdscr.addstr(height - 3, 2, footer_text, curses.color_pair(1))
    stdscr.addstr(height - 3, 2 + len(footer_text), "● Blocked IP", curses.color_pair(8))

    # Use noutrefresh/doupdate for faster rendering
    stdscr.noutrefresh()

def format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info):
    # Concatenate fields into a string with fixed-width columns using '|' as a separator
    return f"{remote_date:<22}|{remote_ip:<16}|{host:<20}|{rule_id:<8}|{attack_name:<40}|{severity:<9}|{response_code:<9}|{payload[:20]}|{info[:20]}|{additional_info[:20]}"

def init_colors():
    global theme_colors
    
    curses.start_color()
    curses.use_default_colors()
    
    # Load the theme from environment or use default
    theme_name = get_theme_from_env()
    load_theme(theme_name)
    
    # Check if terminal supports truecolor
    if curses.can_change_color() and curses.COLORS >= 256:
        # Initialize color palette with theme colors
        color_id = 16  # Start from color 16 to avoid basic colors
        bg_color_id = 100  # Background color ID
        
        # Initialize background color
        if "background" in theme_colors:
            bg_r, bg_g, bg_b = theme_colors["background"]
            bg_r_curses = int((bg_r / 255.0) * 1000)
            bg_g_curses = int((bg_g / 255.0) * 1000)
            bg_b_curses = int((bg_b / 255.0) * 1000)
            curses.init_color(bg_color_id, bg_r_curses, bg_g_curses, bg_b_curses)
        else:
            # Default to black background
            curses.init_color(bg_color_id, 0, 0, 0)
        
        # Map color names to curses color pairs
        color_pair_map = {
            "title_attack": 1,
            "date": 2,
            "ip_address": 3,
            "local_ip_address": 17,  # New color for local IPs
            "rule_id": 4,
            "response_code": 5,
            "severity_base": 6,
            "host": 7,
            "blocked_indicator": 8,
            "severity_emergency": 9,
            "severity_alert": 10,
            "severity_critical": 11,
            "severity_error": 12,
            "severity_warning": 13,
            "severity_notice": 14,
            "severity_info": 15,
            "severity_debug": 16
        }
        
        # Initialize colors and pairs with background
        for color_name, pair_id in color_pair_map.items():
            if color_name in theme_colors:
                r, g, b = theme_colors[color_name]
                # Convert RGB (0-255) to curses range (0-1000)
                r_curses = int((r / 255.0) * 1000)
                g_curses = int((g / 255.0) * 1000)
                b_curses = int((b / 255.0) * 1000)
                
                curses.init_color(color_id, r_curses, g_curses, b_curses)
                curses.init_pair(pair_id, color_id, bg_color_id)  # Use background color
                color_id += 1
    else:
        # Fallback to basic colors for terminals without truecolor support
        curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Title and Attack Name
        curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Date
        curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # IP Address (Remote)
        curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Rule ID
        curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Response Code
        curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)    # Severity
        curses.init_pair(7, curses.COLOR_MAGENTA, curses.COLOR_BLACK)  # Host (Domain Name)
        curses.init_pair(8, curses.COLOR_RED, curses.COLOR_BLACK)     # Blocked indicator
        curses.init_pair(9, curses.COLOR_RED, curses.COLOR_BLACK)     # Emergency
        curses.init_pair(10, curses.COLOR_RED, curses.COLOR_BLACK)    # Alert
        curses.init_pair(11, curses.COLOR_RED, curses.COLOR_BLACK)    # Critical
        curses.init_pair(12, curses.COLOR_RED, curses.COLOR_BLACK)    # Error
        curses.init_pair(13, curses.COLOR_YELLOW, curses.COLOR_BLACK) # Warning
        curses.init_pair(14, curses.COLOR_BLUE, curses.COLOR_BLACK)   # Notice
        curses.init_pair(15, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Info
        curses.init_pair(16, curses.COLOR_CYAN, curses.COLOR_BLACK)   # Debug
        curses.init_pair(17, curses.COLOR_CYAN, curses.COLOR_BLACK)   # IP Address (Local)

def wrap_text(text, width):
    words = text.split()
    lines = []
    current_line = []
    current_length = 0

    for word in words:
        if current_length + len(word + " ") > width:
            lines.append(' '.join(current_line))
            current_line = [word]
            current_length = len(word)
        else:
            current_line.append(word)
            current_length += len(word) + 1

    if current_line:
        lines.append(' '.join(current_line))

    return lines

def show_detailed_entry(stdscr, entry):
    stdscr.clear()
    stdscr.bkgd(' ', curses.color_pair(1))  # Set background
    stdscr.border(0)

    date, ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info = entry.split('|')

    # Process Info section
    info = info.replace('[', '').replace(']', '').strip()

    # Fetch whois information
    whois_info = get_whois_info(ip.strip())

    details = [
        ("Date", date.strip()),
        ("Remote Address", ip.strip()),
        ("Host", host.strip()),
        ("Rule ID", rule_id.strip()),
        ("Attack Name", attack_name.strip()),
        ("Severity", severity.strip()),
        ("Response Code", response_code.strip()),
        ("Payload", payload.strip()),
        ("Info", info.strip()),
    ]

    max_y, max_x = stdscr.getmaxyx()

    # Prepare the text lines
    lines = []
    for title, value in details:
        wrapped_lines = wrap_text(value, max_x - 4)
        lines.append(f"{title}:")
        lines.extend(wrapped_lines)
        lines.append("")  # Add a blank line for spacing

    # Add a space before Additional Info
    lines.append("")

    # Add Additional Info
    lines.append("Additional Info:")
    additional_info_lines = additional_info.split('\n')
    for line in additional_info_lines:
        wrapped_lines = wrap_text(line, max_x - 4)
        lines.extend(wrapped_lines)

    # Add a space before Whois info
    lines.append("")

    # Add Whois Info
    lines.append("Whois:")
    whois_lines = whois_info.split('\n')
    for line in whois_lines:
        wrapped_lines = wrap_text(line, max_x - 4)
        lines.extend(wrapped_lines)

    # Implement scrolling
    current_line = 0
    max_scroll = max(0, len(lines) - (max_y - 4))

    while True:
        stdscr.erase()  # Use erase instead of clear to reduce flickering
        stdscr.bkgd(' ', curses.color_pair(1))  # Set background
        stdscr.border(0)
        stdscr.addstr(0, (max_x - len("Attack Details")) // 2, "Attack Details", curses.color_pair(1) | curses.A_BOLD)
        stdscr.addstr(max_y - 2, (max_x - len("Press <Left Arrow> to return | Up/Down to scroll")) // 2, "Press <Left Arrow> to return | Up/Down to scroll", curses.color_pair(1) | curses.A_BOLD)

        for idx, line in enumerate(lines[current_line:current_line + max_y - 4], start=2):
            stdscr.addstr(idx, 2, line, curses.color_pair(5))

        stdscr.refresh()

        char = stdscr.getch()
        if char in (curses.KEY_BACKSPACE, curses.KEY_LEFT, 127):  # Handle Backspace or Left Arrow key
            break
        elif char == curses.KEY_UP and current_line > 0:
            current_line -= 1
        elif char == curses.KEY_DOWN and current_line < max_scroll:
            current_line += 1

def show_confirmation_window(stdscr, message):
    max_y, max_x = stdscr.getmaxyx()
    win_width = 50
    win_height = 5

    win = curses.newwin(win_height, win_width, (max_y - win_height) // 2, (max_x - win_width) // 2)
    win.bkgd(' ', curses.color_pair(1))  # Set background
    win.border(0)
    win.addstr(1, 2, message, curses.color_pair(1))
    win.addstr(3, 2, "Press 'y' to confirm, 'n' to cancel.", curses.color_pair(1))
    win.refresh()

    while True:
        char = win.getch()
        if char in (ord('y'), ord('Y')):
            return True
        elif char in (ord('n'), ord('N')):
            return False

def show_done_window(stdscr, message):
    max_y, max_x = stdscr.getmaxyx()
    win_width = len(message) + 4
    win_height = 3

    win = curses.newwin(win_height, win_width, (max_y - win_height) // 2, (max_x - win_width) // 2)
    win.bkgd(' ', curses.color_pair(1))  # Set background
    win.border(0)
    win.addstr(1, 2, message, curses.color_pair(1))
    win.refresh()
    time.sleep(3)

def show_theme_selection_window(stdscr):
    """Show theme selection dialog and return selected theme or None if cancelled."""
    try:
        available_themes = get_available_themes()
        if not available_themes:
            show_done_window(stdscr, "No themes available!")
            return None
        
        max_y, max_x = stdscr.getmaxyx()
        win_width = max(50, max(len(theme) for theme in available_themes) + 10)
        win_height = len(available_themes) + 6
        
        # Ensure window fits on screen
        if win_height > max_y - 2:
            win_height = max_y - 2
        if win_width > max_x - 2:
            win_width = max_x - 2
        
        win = curses.newwin(win_height, win_width, (max_y - win_height) // 2, (max_x - win_width) // 2)
        win.keypad(True)  # Enable keypad for arrow keys
        win.bkgd(' ', curses.color_pair(1))  # Set background for dialog
        
        selected_index = 0
        
        # Find current theme index by name matching
        if current_theme:
            for i, theme in enumerate(available_themes):
                # Try to match theme name (case insensitive)
                if theme.lower() == current_theme.lower() or theme.lower() in current_theme.lower():
                    selected_index = i
                    break
    
        while True:
            try:
                win.erase()
                win.border(0)
                
                # Add title
                title = "Select Theme"
                title_x = max(2, (win_width - len(title)) // 2)
                win.addstr(0, title_x, title, curses.color_pair(1) | curses.A_BOLD)
                
                # Display themes list
                for i, theme in enumerate(available_themes):
                    if i + 2 >= win_height - 2:  # Don't exceed window bounds
                        break
                    y_pos = i + 2
                    prefix = "► " if i == selected_index else "  "
                    theme_text = f"{prefix}{theme}"
                    
                    # Truncate if too long
                    if len(theme_text) > win_width - 4:
                        theme_text = theme_text[:win_width - 7] + "..."
                    
                    if i == selected_index:
                        win.addstr(y_pos, 2, theme_text, curses.color_pair(1) | curses.A_REVERSE)
                    else:
                        win.addstr(y_pos, 2, theme_text, curses.color_pair(1))
                
                # Add instructions
                instructions = "Use ↑/↓ to select, Enter to apply, ESC to cancel"
                if len(instructions) > win_width - 4:
                    instructions = "Arrow keys, Enter, ESC"
                win.addstr(win_height - 2, 2, instructions, curses.color_pair(1))
                
                win.refresh()
                
                char = win.getch()
                
                # Handle key presses
                if char == curses.KEY_UP or char == ord('k'):
                    if selected_index > 0:
                        selected_index -= 1
                elif char == curses.KEY_DOWN or char == ord('j'):
                    if selected_index < len(available_themes) - 1:
                        selected_index += 1
                elif char in (curses.KEY_ENTER, 10, 13, ord(' ')):  # Enter or Space
                    return available_themes[selected_index]
                elif char == 27 or char == ord('q'):  # ESC or 'q'
                    return None
                # Ignore all other keys and continue the loop
                
            except curses.error:
                # Handle any curses errors gracefully
                continue
                
    except Exception as e:
        # If anything goes wrong, return None
        return None

def draw_header(stdscr, width):
    start_x = max(0, (width - 125) // 2)  # Adjusted for better fit
    stdscr.addstr(0, 2, "ModSentry 1.0", curses.color_pair(1) | curses.A_BOLD)  # Align to the left with a margin
    stdscr.addstr(1, 2, "by Yodabytz", curses.color_pair(1) | curses.A_BOLD)    # Author name
    stdscr.addstr(2, (width - len("ModSecurity Log Monitor (Press 'q' to quit)")) // 2, "ModSecurity Log Monitor (Press 'q' to quit)", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(3, start_x, f"{'Date':^22} {'IP Address':^16} {'Host':^20} {'Rule ID':^8} {'Attack Name':^37} {'Severity':^9} {'Resp':^8}", curses.color_pair(1) | curses.A_UNDERLINE)

def read_last_entries(log_file_path, max_bytes=102400, max_entries=10):
    """Read the last entries from the log file."""
    with open(log_file_path, 'rb') as f:
        try:
            f.seek(-max_bytes, os.SEEK_END)
        except IOError:
            f.seek(0)
        data = f.read().decode('latin1', errors='ignore')
        # Use regex to split entries
        entries = re.split(r'^--[-\w]+---Z--\n', data, flags=re.MULTILINE)
        entries = [e for e in entries if '---' in e]
        entries = ['--' + e for e in entries if e.strip()]
        return entries[-max_entries:]

def monitor_log_file(stdscr, log_file_path):
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(True)  # Non-blocking input
    
    # Initialize colors with theme support
    theme_name = get_theme_from_env()
    init_colors()
    
    # Set background color for the entire screen
    stdscr.bkgd(' ', curses.color_pair(1))  # Use a color pair for background

    height, width = stdscr.getmaxyx()

    # Check terminal size
    if width < MIN_WIDTH or height < MIN_HEIGHT:
        stdscr.clear()
        stdscr.addstr(0, 0, "Terminal window is too small to display ModSentry. Please resize and try again.", curses.color_pair(8) | curses.A_BOLD)
        stdscr.refresh()
        time.sleep(3)
        return

    log_entries = []
    current_line = 0
    selected_line = 0
    last_draw_state = {}  # Cache for rendering optimization
    needs_full_redraw = True  # Flag for full screen redraw

    check_iptables_chain()  # Ensure the ModSentry chain is ready

    # Read the last entries
    last_entries = read_last_entries(log_file_path, max_entries=10)
    for entry in last_entries:
        remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info = parse_log_entry(entry)
        if rule_id != 'N/A' and rule_id not in IGNORE_RULE_IDS:
            formatted_entry = format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info)
            log_entries.append(formatted_entry)

    # Open the log file and seek to the end
    with open(log_file_path, 'r', encoding='latin1') as log_file:
        log_file.seek(0, os.SEEK_END)
        buffer = ''
        blocked_ips = set()
        last_blocked_ips_update = 0

        while True:
            # Use select to wait for new data or a timeout
            rlist, _, _ = select.select([log_file], [], [], 0.05)  # Faster timeout for responsiveness
            if log_file in rlist:
                line = log_file.readline()
                if line:
                    buffer += line
                    if re.match(r'^--[-\w]+---Z--', line.strip()):
                        # End of an entry
                        entry = buffer
                        buffer = ''
                        # Process the entry
                        remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info = parse_log_entry(entry)
                        if rule_id != 'N/A' and rule_id not in IGNORE_RULE_IDS:
                            formatted_entry = format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info)
                            log_entries.append(formatted_entry)
                            log_entries = log_entries[-MAX_ENTRIES:]  # Keep only the last MAX_ENTRIES entries
                            # Auto-scroll to the bottom when new entries arrive
                            current_line = max(0, len(log_entries) - (height - 8))
                            selected_line = len(log_entries) - 1
                            needs_full_redraw = True  # Mark for redraw on new entry
                            last_draw_state.clear()  # Clear cache on new entries

            # Update blocked_ips every 5 seconds
            current_time = time.time()
            if current_time - last_blocked_ips_update > 5:
                blocked_ips = {line.split()[3] for line in subprocess.run(['iptables', '-L', 'ModSentry', '-n'], capture_output=True, text=True).stdout.splitlines() if line.startswith("DROP")}
                last_blocked_ips_update = current_time

            # Full redraw only when needed
            if needs_full_redraw:
                stdscr.erase()
                stdscr.bkgd(' ', curses.color_pair(1))
                stdscr.border(0)
                draw_header(stdscr, width)
                needs_full_redraw = False

            # Display the last entries that fit the screen height
            display_log_entries(stdscr, log_entries, current_line, selected_line, blocked_ips, last_draw_state)

            # Use doupdate for atomic refresh
            curses.doupdate()

            # Handle scrolling and quitting (non-blocking)
            char = stdscr.getch()
            if char == ord('q'):
                return
            elif char == curses.KEY_UP:
                if selected_line > 0:
                    selected_line -= 1
                    needs_full_redraw = False  # Just update display, don't full clear
                if selected_line < current_line:
                    current_line = selected_line
            elif char == curses.KEY_DOWN:
                if selected_line < len(log_entries) - 1:
                    selected_line += 1
                    needs_full_redraw = False  # Just update display, don't full clear
                if selected_line >= current_line + (height - 8):
                    current_line = selected_line - (height - 9)
            elif char == ord('b'):  # Handle block command
                parts = log_entries[selected_line].split('|')
                _, ip, _, rule_id, attack_name, _, _, _, _, _ = parts
                if show_confirmation_window(stdscr, f"Block IP {ip.strip()}?"):
                    stdscr.addstr(height - 3, 2, f"Blocking IP {ip}...                        ", curses.color_pair(1))
                    stdscr.refresh()
                    # Run the block command with rule_id and attack_name
                    message = block_ip(ip, rule_id, attack_name)
                    stdscr.addstr(height - 3, 2, message + " Press any key to continue.", curses.color_pair(1))
                    stdscr.refresh()
                    stdscr.getch()
                    # Show "Done!" message if successful
                    if "has been blocked" in message:
                        show_done_window(stdscr, "Done!")

            elif char == ord('d'):  # Handle unblock command
                parts = log_entries[selected_line].split('|')
                _, ip, _, rule_id, attack_name, _, _, _, _, _ = parts
                if show_confirmation_window(stdscr, f"Unblock IP {ip.strip()}?"):
                    stdscr.addstr(height - 3, 2, f"Unblocking IP {ip}...                        ", curses.color_pair(1))
                    stdscr.refresh()
                    # Run the unblock command with rule_id and attack_name
                    message = unblock_ip(ip, rule_id, attack_name)
                    stdscr.addstr(height - 3, 2, message + " Press any key to continue.", curses.color_pair(1))
                    stdscr.refresh()
                    stdscr.getch()
                    # Show "Done!" message if successful
                    if "has been unblocked" in message:
                        show_done_window(stdscr, "Done!")

            elif char == ord('t'):  # Handle theme selection
                try:
                    selected_theme = show_theme_selection_window(stdscr)
                    if selected_theme:
                        # Apply the new theme
                        new_theme_name = reinitialize_colors_with_theme(selected_theme)
                        show_done_window(stdscr, f"Theme changed to {new_theme_name}")
                except Exception as e:
                    # If theme switching fails, show error and continue
                    show_done_window(stdscr, "Theme change failed")
                # Always refresh the main screen
                stdscr.erase()
                # Set background color after theme change
                stdscr.bkgd(' ', curses.color_pair(1))
                stdscr.border(0)
                draw_header(stdscr, width)
                continue
            elif char == ord('i'):  # Handle ignore rule command
                # Get the rule ID from the selected entry
                parts = log_entries[selected_line].split('|')
                rule_id = parts[3].strip() if len(parts) > 3 else 'N/A'

                if rule_id != 'N/A':
                    if show_confirmation_window(stdscr, f"Add rule {rule_id} to ignore list?"):
                        if add_ignore_rule(rule_id):
                            show_done_window(stdscr, f"Rule {rule_id} added to ignore list")
                        else:
                            show_done_window(stdscr, f"Rule {rule_id} already ignored or failed")
                else:
                    show_done_window(stdscr, "Cannot add N/A rule")
                stdscr.erase()
                stdscr.bkgd(' ', curses.color_pair(1))
                stdscr.border(0)
                draw_header(stdscr, width)
                continue
            elif char in (curses.KEY_ENTER, 10, 13):  # Handle Enter key
                show_detailed_entry(stdscr, log_entries[selected_line])
                stdscr.erase()  # Use erase to clear without flicker
                # Restore background color after detailed view
                stdscr.bkgd(' ', curses.color_pair(1))
                stdscr.border(0)
                draw_header(stdscr, width)
                continue  # Continue the loop to refresh the main screen

def display_help():
    available_themes = get_available_themes()
    theme_list = ", ".join(available_themes) if available_themes else "No themes found"

    help_message = f"""
ModSentry v{VERSION} - ModSecurity Log Monitor

Usage:
  modsentry [options]

Options:
  -h, --help  Show this help message and exit
  -t, --theme THEME  Set theme (default, dark, solarized, tokyonight, dracula, gruvbox)

Controls:
  Enter  Show more info about the selected entry
  b      Block the IP address of the selected entry
  d      Unblock the IP address of the selected entry
  i      Add rule ID to ignore list (won't display alerts for this rule)
  t      Change theme (live theme switching)
  q      Quit the application

Phase 1 Features:
  - Audit trail logging: /var/log/modsentry-audit.log
  - Persistent IP blocks: /etc/modsentry/blocked-ips.conf
  - Whitelist support: /etc/modsentry/whitelist.conf
  - iptables rule ordering (rules checked first)
  - Local/remote IP differentiation with color coding

Theme Support:
  Set MODSENTRY_THEME environment variable to change themes.
  Available themes: {theme_list}
  Default theme: {DEFAULT_THEME}

  Example: MODSENTRY_THEME=dark modsentry

Description:
  ModSentry is a real-time log monitoring tool for ModSecurity logs.
  It allows you to view and analyze security events, block suspicious IPs,
  and maintain audit trails for compliance (SOC2, PCI-DSS, HIPAA).
  Supports truecolor themes for enhanced visual experience over SSH/tmux.

Requirements:
  - Run as root or with sudo privileges for iptables access.
"""

    print(help_message)

def main():
    # Load configuration from file
    load_config()
    load_ignore_rules()

    # Set up argument parser
    parser = argparse.ArgumentParser(description='ModSentry - ModSecurity Log Monitor', add_help=False)
    parser.add_argument('-h', '--help', action='store_true', help='Show this help message and exit')
    parser.add_argument('-t', '--theme', type=str, help='Theme to use (overrides MODSENTRY_THEME environment variable)')
    
    try:
        args = parser.parse_args()
    except SystemExit:
        return
    
    # Handle help
    if args.help:
        display_help()
        return
    
    # Set theme from command line if provided
    if args.theme:
        # Handle theme aliases
        theme_name = args.theme.lower()
        if theme_name in ['tokyo_nights', 'tokyo-nights', 'tokyonights']:
            theme_name = 'tokyonight'
        os.environ['MODSENTRY_THEME'] = theme_name
    
    # Check if the script is run with root privileges
    if os.geteuid() != 0:
        print("This script must be run as root to access iptables. Please run with sudo.")
        return
    
    curses.wrapper(monitor_log_file, LOG_FILE_PATH)

if __name__ == "__main__":
    main()
