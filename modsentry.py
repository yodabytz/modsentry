import re
import time
import curses
import os

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

    # Extract values, fallback to 'N/A' if not found
    remote_date = date_match.group(1) if date_match else 'N/A'
    remote_ip = ip_match.group(1) if ip_match else 'N/A'  # Extract the IP address
    host = host_match.group(1) if host_match else 'N/A'
    rule_id = rule_id_match.group(1) if rule_id_match else 'N/A'
    attack_name = attack_name_match.group(1) if attack_name_match else 'N/A'
    severity = severity_match.group(1) if severity_match else 'N/A'
    response_code = response_code_match.group(1) if response_code_match else 'N/A'

    return remote_date, remote_ip, host, rule_id, attack_name, severity, response_code

# Function to display log entries with curses
def display_log_entries(stdscr, log_entries, current_line):
    height, width = stdscr.getmaxyx()

    # Display log entries with colors for each column
    for idx, entry in enumerate(log_entries[current_line:current_line + height - 6], start=4):
        stdscr.move(idx, 1)
        stdscr.clrtoeol()  # Clear the current line before updating

        # Split the formatted entry into its components
        date, ip, host, rule_id, attack_name, severity, response_code = entry.split('|')

        # Calculate positions to center the data
        stdscr.addnstr(idx, (width - 128) // 2 + 1, date.strip(), 22, curses.color_pair(2))
        stdscr.addnstr(idx, (width - 128) // 2 + 24, ip.strip(), 15, curses.color_pair(3))
        stdscr.addnstr(idx, (width - 128) // 2 + 40, host.strip(), 20, curses.color_pair(7))  # Bright yellow
        stdscr.addnstr(idx, (width - 128) // 2 + 61, rule_id.strip(), 8, curses.color_pair(5))
        stdscr.addnstr(idx, (width - 128) // 2 + 70, attack_name.strip(), 35, curses.color_pair(1))  # Cyan
        stdscr.addnstr(idx, (width - 128) // 2 + 106, severity.strip().center(9), 9, curses.color_pair(5))  # Center severity
        stdscr.addnstr(idx, (width - 128) // 2 + 116, response_code.strip(), 9, curses.color_pair(5))

    stdscr.refresh()

# Function to format a log entry
def format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code):
    # Concatenate fields into a string with fixed-width columns using '|' as a separator
    return f"{remote_date:<22.22}|{remote_ip:<15.15}|{host:<20.20}|{rule_id:<8.8}|{attack_name:<35.35}|{severity:<9.9}|{response_code:<9.9}"

# Function to initialize colors
def init_colors():
    curses.start_color()
    curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)    # Title and Attack Name
    curses.init_pair(2, curses.COLOR_GREEN, curses.COLOR_BLACK)   # Date
    curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # IP Address
    curses.init_pair(4, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Rule ID and Response Code
    curses.init_pair(5, curses.COLOR_WHITE, curses.COLOR_BLACK)   # Rule ID and Response Code
    curses.init_pair(6, curses.COLOR_BLUE, curses.COLOR_BLACK)    # Severity
    curses.init_pair(7, curses.COLOR_YELLOW, curses.COLOR_BLACK)  # Host (Domain Name)

# Function to monitor the log file
def monitor_log_file(stdscr, log_file_path):
    curses.curs_set(0)  # Hide cursor
    stdscr.nodelay(True)  # Non-blocking input
    init_colors()

    log_entries = []
    current_line = 0

    # Draw the static elements of the UI once
    stdscr.clear()
    stdscr.border(0)
    stdscr.addstr(0, (stdscr.getmaxyx()[1] - len("ModSentry 1.0")) // 2, "ModSentry 1.0", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(1, (stdscr.getmaxyx()[1] - len("ModSecurity Log Monitor (Press 'q' to quit)")) // 2, "ModSecurity Log Monitor (Press 'q' to quit)", curses.color_pair(1) | curses.A_BOLD)
    stdscr.addstr(2, (stdscr.getmaxyx()[1] - 128) // 2, f"{'Date':^22} {'IP Address':^15} {'Host':^20} {'Rule ID':^8} {'Attack Name':^35} {'Severity':^9} {'Resp. Code':^9}", curses.color_pair(1) | curses.A_UNDERLINE)
    stdscr.refresh()

    try:
        with open(log_file_path, 'r') as log_file:
            # Read the file backwards to get the last 10 entries
            lines = log_file.readlines()
            buffer = ''
            entries = []

            for line in reversed(lines):
                buffer = line + buffer
                if line.startswith("---") and "A--" in line:
                    remote_date, remote_ip, host, rule_id, attack_name, severity, response_code = parse_log_entry(buffer)
                    # Only append if there's a Rule ID
                    if rule_id != 'N/A':
                        formatted_entry = format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code)
                        entries.append(formatted_entry)
                    buffer = ''  # Clear buffer for the next entry

                if len(entries) >= 10:
                    break

            log_entries.extend(reversed(entries))  # Reverse to maintain the order
            log_file.seek(0, os.SEEK_END)  # Move to the end of the file

            buffer = ''
            while True:
                # Read only new lines
                lines = log_file.read()
                if lines:
                    buffer += lines
                    entries = buffer.split('---Z--\n')  # Split log entries by end marker
                    buffer = entries[-1]  # Keep the last partial entry in buffer

                    for entry in entries[:-1]:
                        remote_date, remote_ip, host, rule_id, attack_name, severity, response_code = parse_log_entry(entry)
                        # Only append if there's a Rule ID
                        if rule_id != 'N/A':
                            formatted_entry = format_entry(remote_date, remote_ip, host, rule_id, attack_name, severity, response_code)
                            log_entries.append(formatted_entry)
                            log_entries = log_entries[-1000:]  # Keep only the last 1000 entries

                # Refresh the screen dimensions
                height, _ = stdscr.getmaxyx()
                # Automatically scroll if we are at the bottom of the list
                if current_line >= len(log_entries) - (height - 6):
                    current_line = max(0, len(log_entries) - (height - 6))

                # Display the last entries that fit the screen height
                display_log_entries(stdscr, log_entries[current_line:], current_line)

                # Handle scrolling and quitting
                char = stdscr.getch()
                if char == ord('q'):
                    break
                elif char == curses.KEY_UP and current_line > 0:
                    current_line -= 1
                elif char == curses.KEY_DOWN and current_line < len(log_entries) - (height - 6):
                    current_line += 1

                time.sleep(0.1)  # Reduce CPU usage

    except FileNotFoundError:
        stdscr.addstr(0, 0, f"Error: Log file {log_file_path} not found.", curses.color_pair(1))
        stdscr.refresh()
        time.sleep(3)

def main():
    log_file_path = "/var/log/modsec_audit.log"
    curses.wrapper(monitor_log_file, log_file_path)

if __name__ == "__main__":
    main()
