#!/usr/bin/env python3

import re
import time
import curses
import os
import subprocess
import sys
import whois
import select

# Configuration Variables
LOG_FILE_PATH = "/var/log/modsec_audit.log"  # Path to the log file
IGNORE_RULE_IDS = {"930130", "941100", "933120", "12345", "67890", "953100"}  # Set of rule IDs to ignore
MIN_WIDTH = 128  # Minimum width for the terminal
MIN_HEIGHT = 24  # Minimum height for the terminal
MAX_ENTRIES = 200  # Maximum number of entries to remember

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

# Mapping of severity descriptions to colors
SEVERITY_COLOR_MAP = {
    "Emergency": 8,  # Bright Red
    "Alert": 8,
    "Critical": 8,
    "Error": 8,
    "Warning": 9,   # Yellow
    "Notice": 10,   # Bright Blue
    "Info": 11,     # Bright Green
    "Debug": 12     # Bright Cyan
}

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
    except subprocess.CalledProcessError:
        # Create the ModSentry chain if it doesn't exist
        subprocess.run(['iptables', '-N', 'ModSentry'], check=True)
        # Insert the ModSentry chain into the INPUT chain
        subprocess.run(['iptables', '-I', 'INPUT', '-j', 'ModSentry'], check=True)

def is_ip_blocked(ip):
    """Check if the given IP is already blocked in the ModSentry chain."""
    result = subprocess.run(['iptables', '-L', 'ModSentry', '-n'], capture_output=True, text=True)
    return ip in result.stdout

def block_ip(ip):
    """Block the given IP address using iptables."""
    try:
        # Trim whitespace from the IP address
        ip = ip.strip()
        if not is_ip_blocked(ip):
            subprocess.run(['iptables', '-A', 'ModSentry', '-s', ip, '-j', 'DROP'], check=True)
            return f"IP {ip} has been blocked."
        else:
            return f"IP {ip} is already blocked."
    except subprocess.CalledProcessError as e:
        return f"Failed to block IP {ip}: {str(e)}"

def unblock_ip(ip):
    """Unblock the given IP address using iptables."""
    try:
        # Trim whitespace from the IP address
        ip = ip.strip()
        if is_ip_blocked(ip):
            subprocess.run(['iptables', '-D', 'ModSentry', '-s', ip, '-j', 'DROP'], check=True)
            return f"IP {ip} has been unblocked."
        else:
            return f"IP {ip} is not blocked."
    except subprocess.CalledProcessError as e:
        return f"Failed to unblock IP {ip}: {str(e)}"

def parse_log_entry(entry):
    # Extract the date from section A
    date_match = re.search(r'^---.*?---A--\n\[(.*?)\]', entry, re.MULTILINE)
    remote_date = date_match.group(1) if date_match else 'N/A'

    # Extract the remote IP from section A
    ip_match = re.search(r'^---.*?---A--\n\[.*?\]\s+\S+\s+(\d{1,3}(?:\.\d{1,3}){3})', entry, re.MULTILINE)
    remote_ip = ip_match.group(1) if ip_match else 'N/A'

    # Extract host from section B
    host_match = re.search(r'^Host:\s*(.+)$', entry, re.MULTILINE)
    host = host_match.group(1).strip() if host_match else 'N/A'

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

def display_log_entries(stdscr, log_entries, current_line, selected_line, blocked_ips):
    height, width = stdscr.getmaxyx()

    # Display log entries with colors for each column
    for idx, entry in enumerate(log_entries[current_line:current_line + height - 8], start=4):
        stdscr.move(idx, 1)
        stdscr.clrtoeol()  # Clear the current line before updating

        # Split the formatted entry into its components
        parts = entry.split('|')
        if len(parts) != 10:
            # Skip malformed entries
            continue

        date, ip, host, rule_id, attack_name, severity, response_code, _, _, _ = parts

        # Determine if this line is the currently selected one
        is_selected = current_line + idx - 4 == selected_line

        # Determine if the IP is blocked
        is_blocked = ip.strip() in blocked_ips

        # Calculate positions to center the data
        start_x = max(0, (width - 128) // 2)  # Ensure start_x is not negative

        # Add a red dot for blocked IPs
        if is_blocked:
            stdscr.addstr(idx, start_x - 2, '●', curses.color_pair(8))  # Bright Red dot

        # Display the log entry
        stdscr.addnstr(idx, start_x, date.strip(), 22, curses.color_pair(2) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 23, ip.strip(), 16, curses.color_pair(3) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 40, host.strip(), 20, curses.color_pair(7) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 60, rule_id.strip(), 8, curses.color_pair(4) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 69, attack_name.strip(), 40, curses.color_pair(1) | (curses.A_REVERSE if is_selected else 0))

        # Apply appropriate color to the severity based on the mapping
        severity_color = SEVERITY_COLOR_MAP.get(severity.strip(), 5)
        stdscr.addnstr(idx, start_x + 110, severity.strip().center(9), 9, curses.color_pair(severity_color) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 120, response_code.strip().center(9), 9, curses.color_pair(5) | (curses.A_REVERSE if is_selected else 0))

    # Add the block IP message at the bottom
    stdscr.addstr(height - 3, 2, "Enter: More Info | 'b': Block IP | 'd': Unblock IP | 'q': Quit | ● Blocked IP", curses.color_pair(1))
    stdscr.refresh()

def format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info):
    # Concatenate fields into a string with fixed-width columns using '|' as a separator
    return f"{remote_date:<22}|{remote_ip:<16}|{host:<20}|{rule_id:<8}|{attack_name:<40}|{severity:<9}|{response_code:<9}|{payload[:20]}|{info[:20]}|{additional_info[:20]}"

def init_colors():
    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_CYAN, -1)    # Title and Attack Name
    curses.init_pair(2, curses.COLOR_GREEN, -1)   # Date
    curses.init_pair(3, curses.COLOR_YELLOW, -1)  # IP Address
    curses.init_pair(4, curses.COLOR_WHITE, -1)   # Rule ID
    curses.init_pair(5, curses.COLOR_WHITE, -1)   # Response Code
    curses.init_pair(6, curses.COLOR_BLUE, -1)    # Severity
    curses.init_pair(7, curses.COLOR_YELLOW, -1)  # Host (Domain Name)

    # Define bright colors for severity levels
    curses.init_pair(8, curses.COLOR_RED, -1)     # Bright Red
    curses.init_pair(9, curses.COLOR_YELLOW, -1)  # Yellow
    curses.init_pair(10, curses.COLOR_BLUE, -1)   # Bright Blue
    curses.init_pair(11, curses.COLOR_GREEN, -1)  # Bright Green
    curses.init_pair(12, curses.COLOR_CYAN, -1)   # Bright Cyan

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
    win.border(0)
    win.addstr(1, 2, message, curses.color_pair(1))
    win.refresh()
    time.sleep(3)

def draw_header(stdscr, width):
    start_x = max(0, (width - 128) // 2)  # Ensure start_x is not negative
    stdscr.addstr(0, 2, "ModSentry 1.0", curses.color_pair(1) | curses.A_BOLD)  # Align to the left with a margin
    stdscr.addstr(1, 2, "by Yodabytz", curses.color_pair(1) | curses.A_BOLD)    # Author name
    stdscr.addstr(2, (width - len("ModSecurity Log Monitor (Press 'q' to quit)")) // 2, "ModSecurity Log Monitor (Press 'q' to quit)", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(3, start_x, f"{'Date':^22} {'IP Address':^16} {'Host':^20} {'Rule ID':^8} {'Attack Name':^40} {'Severity':^9} {'Resp. Code':^9}", curses.color_pair(1) | curses.A_UNDERLINE)

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
    init_colors()

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
            rlist, _, _ = select.select([log_file], [], [], 0.1)
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
                else:
                    # EOF reached
                    time.sleep(0.1)

            # Update blocked_ips every 5 seconds
            current_time = time.time()
            if current_time - last_blocked_ips_update > 5:
                blocked_ips = {line.split()[3] for line in subprocess.run(['iptables', '-L', 'ModSentry', '-n'], capture_output=True, text=True).stdout.splitlines() if line.startswith("DROP")}
                last_blocked_ips_update = current_time

            # Clear only when drawing to prevent flicker
            stdscr.erase()
            stdscr.border(0)
            draw_header(stdscr, width)
            # Display the last entries that fit the screen height
            display_log_entries(stdscr, log_entries, current_line, selected_line, blocked_ips)

            # Handle scrolling and quitting
            char = stdscr.getch()
            if char == ord('q'):
                return
            elif char == curses.KEY_UP:
                if selected_line > 0:
                    selected_line -= 1
                if selected_line < current_line:
                    current_line = selected_line
            elif char == curses.KEY_DOWN:
                if selected_line < len(log_entries) - 1:
                    selected_line += 1
                if selected_line >= current_line + (height - 8):
                    current_line = selected_line - (height - 9)
            elif char == ord('b'):  # Handle block command
                _, ip, _, _, _, _, _, _, _, _ = log_entries[selected_line].split('|')
                if show_confirmation_window(stdscr, f"Block IP {ip.strip()}?"):
                    stdscr.addstr(height - 3, 2, f"Blocking IP {ip}...                        ", curses.color_pair(1))
                    stdscr.refresh()
                    # Run the block command
                    message = block_ip(ip)
                    stdscr.addstr(height - 3, 2, message + " Press any key to continue.", curses.color_pair(1))
                    stdscr.refresh()
                    stdscr.getch()
                    # Show "Done!" message if successful
                    if "has been blocked" in message:
                        show_done_window(stdscr, "Done!")

            elif char == ord('d'):  # Handle unblock command
                _, ip, _, _, _, _, _, _, _, _ = log_entries[selected_line].split('|')
                if show_confirmation_window(stdscr, f"Unblock IP {ip.strip()}?"):
                    stdscr.addstr(height - 3, 2, f"Unblocking IP {ip}...                        ", curses.color_pair(1))
                    stdscr.refresh()
                    # Run the unblock command
                    message = unblock_ip(ip)
                    stdscr.addstr(height - 3, 2, message + " Press any key to continue.", curses.color_pair(1))
                    stdscr.refresh()
                    stdscr.getch()
                    # Show "Done!" message if successful
                    if "has been unblocked" in message:
                        show_done_window(stdscr, "Done!")

            elif char in (curses.KEY_ENTER, 10, 13):  # Handle Enter key
                show_detailed_entry(stdscr, log_entries[selected_line])
                stdscr.erase()  # Use erase to clear without flicker
                stdscr.border(0)
                draw_header(stdscr, width)
                continue  # Continue the loop to refresh the main screen

def display_help():
    help_message = """
ModSentry - ModSecurity Log Monitor

Usage:
  modsentry [options]

Options:
  -h, --help  Show this help message and exit

Controls:
  Enter  Show more info about the selected entry
  b      Block the IP address of the selected entry
  d      Unblock the IP address of the selected entry
  q      Quit the application

Description:
  ModSentry is a real-time log monitoring tool for ModSecurity logs.
  It allows you to view and analyze security events, and block suspicious IPs.

Requirements:
  - Run as root or with sudo privileges for iptables access.
"""

    print(help_message)

def main():
    # Check for command line arguments
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-h', '--help'):
            display_help()
            return

    # Check if the script is run with root privileges
    if os.geteuid() != 0:
        print("This script must be run as root to access iptables. Please run with sudo.")
        return
    curses.wrapper(monitor_log_file, LOG_FILE_PATH)

if __name__ == "__main__":
    main()
