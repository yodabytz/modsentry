#!/usr/bin/env python3

import re
import time
import curses
import os

# Configuration Variables
LOG_FILE_PATH = "/var/log/modsec_audit.log"  # Path to the log file
IGNORE_RULE_IDS = {"12345", "67890", "953100"}  # Set of rule IDs to ignore (add your false positives here)
MIN_WIDTH = 128  # Minimum width for the terminal
MIN_HEIGHT = 24  # Minimum height for the terminal

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

# Function to parse a single log entry
def parse_log_entry(entry):
    # Use regex to extract necessary fields from the log entry
    date_match = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]', entry)
    # Regex to extract the IP address from Section A
    ip_match = re.search(r'---A--\n\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] \S+ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', entry)
    host_match = re.search(r'Host: ([^\s]+)', entry)
    rule_id_match = re.search(r'\[id "(\d+)"\]', entry)
    attack_name_match = re.search(r'\[msg "(.*?)"( via [^"]+)?\]', entry)  # Remove "via" part
    severity_match = re.search(r'\[severity "(\d+)"\]', entry)
    response_code_match = re.search(r'HTTP/1.[01] (\d{3})', entry)
    payload_match = re.search(r'---B--\n(.*?)\n---', entry, re.DOTALL)  # Payload extraction from section B
    info_match = re.search(r'---H--\n(.*?)\n---', entry, re.DOTALL)     # Info extraction from section H
    additional_info_match = re.search(r'---F--\n(.*?)\n---', entry, re.DOTALL)  # Additional info from section F

    # Extract values, fallback to 'N/A' if not found
    remote_date = date_match.group(1) if date_match else 'N/A'
    remote_ip = ip_match.group(1) if ip_match else 'N/A'  # Extract the IP address
    host = host_match.group(1) if host_match else 'N/A'
    rule_id = rule_id_match.group(1) if rule_id_match else 'N/A'
    attack_name = attack_name_match.group(1) if attack_name_match else 'N/A'
    severity = SEVERITY_MAP.get(severity_match.group(1), "N/A") if severity_match else 'N/A'
    response_code = response_code_match.group(1) if response_code_match else 'N/A'
    payload = payload_match.group(1).strip() if payload_match else 'N/A'
    info = info_match.group(1).strip() if info_match else 'N/A'
    additional_info = additional_info_match.group(1).strip() if additional_info_match else 'N/A'

    return remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info

# Function to display log entries with curses
def display_log_entries(stdscr, log_entries, current_line, selected_line):
    height, width = stdscr.getmaxyx()

    # Display log entries with colors for each column
    for idx, entry in enumerate(log_entries[current_line:current_line + height - 6], start=4):
        stdscr.move(idx, 1)
        stdscr.clrtoeol()  # Clear the current line before updating

        # Split the formatted entry into its components
        parts = entry.split('|')
        if len(parts) != 10:
            # Skip malformed entries
            continue

        date, ip, host, rule_id, attack_name, severity, response_code, _, _, _ = parts

        # Determine if this line is the currently selected one
        is_selected = idx - 4 == selected_line

        # Calculate positions to center the data
        start_x = max(0, (width - 128) // 2)  # Ensure start_x is not negative
        stdscr.addnstr(idx, start_x, date.strip(), 22, curses.color_pair(2) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 23, ip.strip(), 15, curses.color_pair(3) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 39, host.strip(), 20, curses.color_pair(7) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 60, rule_id.strip(), 8, curses.color_pair(4) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 69, attack_name.strip(), 35, curses.color_pair(1) | (curses.A_REVERSE if is_selected else 0))

        # Apply appropriate color to the severity based on the mapping
        severity_color = SEVERITY_COLOR_MAP.get(severity, 5)
        stdscr.addnstr(idx, start_x + 105, severity.strip().center(9), 9, curses.color_pair(severity_color) | (curses.A_REVERSE if is_selected else 0))
        stdscr.addnstr(idx, start_x + 115, response_code.strip().center(9), 9, curses.color_pair(5) | (curses.A_REVERSE if is_selected else 0))

    stdscr.refresh()

# Function to format a log entry
def format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info):
    # Concatenate fields into a string with fixed-width columns using '|' as a separator
    return f"{remote_date:<22.22}|{remote_ip:<15.15}|{host:<20.20}|{rule_id:<8.8}|{attack_name:<35.35}|{severity:<9.9}|{response_code:<9.9}|{payload}|{info}|{additional_info}"

# Function to initialize colors
def init_colors():
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Title and Attack Name
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Date
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # IP Address
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Rule ID
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Response Code
    curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)    # Severity
    curses.init_pair(7, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Host (Domain Name)

    # Define bright colors for severity levels
    curses.init_pair(8, curses.COLOR_RED, curses.COLOR_BLACK)     # Bright Red
    curses.init_pair(9, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Yellow
    curses.init_pair(10, curses.COLOR_BLUE, curses.COLOR_BLACK)   # Bright Blue
    curses.init_pair(11, curses.COLOR_GREEN, curses.COLOR_BLACK)  # Bright Green
    curses.init_pair(12, curses.COLOR_CYAN, curses.COLOR_BLACK)   # Bright Cyan

# Function to wrap text to fit within the screen width
def wrap_text(text, width):
    words = text.split()
    lines = []
    current_line = []
    current_length = 0

    for word in words:
        if current_length + len(word) + len(current_line) > width:
            lines.append(' '.join(current_line))
            current_line = [word]
            current_length = len(word)
        else:
            current_line.append(word)
            current_length += len(word)

    if current_line:
        lines.append(' '.join(current_line))

    return lines

# Function to show detailed information of a selected entry
def show_detailed_entry(stdscr, entry):
    stdscr.clear()
    stdscr.border(0)

    date, ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info = entry.split('|')

    # Process Info section
    info = info.replace('[', '').replace(']', '').strip()

    details = [
        ("Date", date.strip()),
        ("Remote Address", ip.strip()),  # Changed from IP Address to Remote Address
        ("Host", host.strip()),
        ("Rule ID", rule_id.strip()),
        ("Attack Name", attack_name.strip()),
        ("Severity", severity.strip()),
        ("Response Code", response_code.strip()),
        ("Payload", payload.strip()),
        ("Info", info.strip())
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

    # Implement scrolling
    current_line = 0
    max_scroll = len(lines) - (max_y - 4)

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

# Function to draw the header
def draw_header(stdscr, width):
    start_x = max(0, (width - 128) // 2)  # Ensure start_x is not negative
    stdscr.addstr(0, 2, "ModSentry 1.0", curses.color_pair(1) | curses.A_BOLD)  # Align to the left with a margin
    stdscr.addstr(1, 2, "by Yodabytz", curses.color_pair(1) | curses.A_BOLD)    # Author name
    stdscr.addstr(2, (width - len("ModSecurity Log Monitor (Press 'q' to quit)")) // 2, "ModSecurity Log Monitor (Press 'q' to quit)", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(3, start_x, f"{'Date':^22} {'IP Address':^15} {'Host':^20} {'Rule ID':^8} {'Attack Name':^35} {'Severity':^9} {'Resp. Code':^9}", curses.color_pair(1) | curses.A_UNDERLINE)

# Function to monitor the log file
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

    with open(log_file_path, 'r') as log_file:
        # Read the file backwards to get the last 10 entries
        lines = log_file.readlines()
        buffer = ''
        entries = []

        for line in reversed(lines):
            buffer = line + buffer
            if line.startswith("---") and "A--" in line:
                remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info = parse_log_entry(buffer)
                # Only append if there's a Rule ID and it's not in the ignore list
                if rule_id != 'N/A' and rule_id not in IGNORE_RULE_IDS:
                    formatted_entry = format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info)
                    entries.append(formatted_entry)
                buffer = ''  # Clear buffer for the next entry

            if len(entries) >= 10:
                break

        log_entries.extend(reversed(entries))  # Reverse to maintain the order
        log_file.seek(0, os.SEEK_END)  # Move to the end of the file

        buffer = ''
        last_position = log_file.tell()  # Track the last position
        while True:
            # Clear only when drawing to prevent flicker
            stdscr.erase()
            stdscr.border(0)
            draw_header(stdscr, width)

            # Read only new lines
            log_file.seek(last_position)
            lines = log_file.read()
            if lines:
                buffer += lines
                entries = buffer.split('---Z--\n')  # Split log entries by end marker
                buffer = entries[-1]  # Keep the last partial entry in buffer

                for entry in entries[:-1]:
                    remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info = parse_log_entry(entry)
                    # Only append if there's a Rule ID and it's not in the ignore list
                    if rule_id != 'N/A' and rule_id not in IGNORE_RULE_IDS:
                        formatted_entry = format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code, payload, info, additional_info)
                        log_entries.append(formatted_entry)
                        log_entries = log_entries[-1000:]  # Keep only the last 1000 entries

            last_position = log_file.tell()  # Update the last position

            # Automatically scroll if we are at the bottom of the list
            if current_line >= len(log_entries) - (height - 7):
                current_line = max(0, len(log_entries) - (height - 7))

            # Display the last entries that fit the screen height
            display_log_entries(stdscr, log_entries, current_line, selected_line)

            # Handle scrolling and quitting
            char = stdscr.getch()
            if char == ord('q'):
                return
            elif char == curses.KEY_UP and selected_line > 0:
                selected_line -= 1
                if selected_line < current_line:
                    current_line -= 1
            elif char == curses.KEY_DOWN and selected_line < len(log_entries) - 1:
                selected_line += 1
                if selected_line >= current_line + (height - 7):
                    current_line += 1
            elif char in (curses.KEY_ENTER, 10, 13):  # Handle Enter key
                show_detailed_entry(stdscr, log_entries[selected_line])
                stdscr.erase()  # Use erase to clear without flicker
                stdscr.border(0)
                draw_header(stdscr, width)
                log_file.seek(last_position)  # Ensure we continue from the correct position
                continue  # Continue the loop to refresh the main screen

            time.sleep(0.1)  # Reduce CPU usage

def main():
    curses.wrapper(monitor_log_file, LOG_FILE_PATH)

if __name__ == "__main__":
    main()
