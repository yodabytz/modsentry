## ModSentry 1.5

ModSentry is a real-time log monitoring tool for analyzing security events from ModSecurity logs. It provides an intuitive terminal interface to track alerts and highlight critical incidents. IP addresses can be blocked or unblocked using `iptables` directly from the interface. Features production-ready security capabilities including audit trail logging, persistent IP blocks that survive reboots, and compliance-ready configurations. For this script to work, ModSecurity must be set to Serial logging. Theme support with truecolor is now available.

## Table of Contents

- [Getting Started](#getting-started)
- [Requirements](#Requirements)
- [Installation](#installation)
- [Screen Shots](#screenshots)
- [Features](#features)
- [Usage](#usage)
- [Controls](#controls)
- [License](#license)

## Getting Started

These instructions will help you set up and run ModSentry on your local machine for development and testing.

## Requirements

- Python 3.x
- `whois`
- `curses` library (pre-installed with Python on most Unix-based systems)
- Root or sudo access for iptables management

## Installation

Clone the repository:

bash
```
git clone https://github.com/your_username/modsentry.git
cd modsentry
sudo cp modsentry.py /usr/bin/modsentry
```
## Screenshots
<img src="https://raw.githubusercontent.com/yodabytz/modsentry/refs/heads/main/modsentry.png?raw=true" width="600">
<img src="https://raw.githubusercontent.com/yodabytz/modsentry/refs/heads/main/modsentry_info.png?raw=true" width="600">

## Features

### Core Features
- Real-time Monitoring: Automatically updates to display new log entries.
- Color-Coded Alerts: Quickly identify critical issues with color-coded severity levels.
- IP Blocking/Unblocking: Block and unblock suspicious IP addresses directly from the interface using iptables.
- Popup Confirmation: Confirmation dialogs for blocking/unblocking IPs and successful actions.
- Scrollable Interface: Navigate through logs and detailed views with ease.
- Whois Information: Fetch detailed Whois information for IP addresses.
- Help Command: View usage instructions and controls via the `-h` switch.
- Theme Support: Multiple color themes with truecolor support for SSH/tmux.

### Phase 1 Features (v1.5)
- **Audit Trail Logging**: All block/unblock actions logged to `/var/log/modsentry-audit.log` with timestamp, user, rule ID, and status
- **Persistent IP Blocks**: Blocked IPs saved to `/etc/modsentry/blocked-ips.conf` and automatically restored on system reboot
- **Whitelist Configuration**: Trusted IP whitelist support via `/etc/modsentry/whitelist.conf`
- **iptables Rule Ordering**: ModSentry chain inserted at position 1 in INPUT chain for maximum security
- **Local/Remote IP Differentiation**: Different color coding for local vs. remote IP addresses
- **Compliance Ready**: SOC2, PCI-DSS, and HIPAA audit trail support

## Functions

### Core Functions
- `parse_log_entry(entry)` - Parses ModSecurity log entries and extracts relevant fields
- `format_entry()` - Formats parsed log entries for display
- `display_log_entries()` - Renders log entries to the terminal interface
- `show_detailed_entry()` - Shows detailed information about a selected log entry
- `check_iptables_chain()` - Ensures ModSentry iptables chain exists and is properly positioned

### IP Management Functions
- `block_ip(ip, rule_id, attack_name)` - Blocks an IP address with audit logging and persistence
- `unblock_ip(ip, rule_id, attack_name)` - Unblocks an IP address with audit logging and persistence
- `is_ip_blocked(ip)` - Checks if an IP is currently blocked in iptables
- `is_local_ip(ip_str)` - Detects if an IP is local/private (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)

### Audit & Persistence Functions
- `log_audit_action(action, ip_address, rule_id, attack_name, status, details)` - Logs actions to audit trail
- `save_blocked_ip_to_file(ip)` - Persists blocked IP to configuration file
- `remove_blocked_ip_from_file(ip)` - Removes IP from persistent blocked list
- `restore_blocked_ips_from_file()` - Restores blocked IPs from config on startup
- `load_whitelist()` - Loads trusted IPs from whitelist configuration

### UI Functions
- `display_help()` - Shows help message with version and features
- `show_confirmation_window(stdscr, prompt)` - Displays confirmation dialog
- `show_whois_lookup_window(stdscr, ip)` - Displays Whois information for an IP
- `show_theme_selection_window(stdscr)` - Allows live theme switching

## Usage
Run the application with the following command:
```
sudo modsentry
sudo modsentry -h
```
### Controls
```
Enter/Return: Show more info about the selected entry.
b:           Block the IP address of the selected entry (with audit logging).
d:           Unblock the IP address of the selected entry (with audit logging).
t:           Open theme selection menu for live theme switching.
q:           Quit the application.
Up/Down:     Navigate through log entries.
Left/Backsp: Return to the main screen from a detailed view.
```

### Audit Trail
ModSentry maintains a complete audit trail for compliance:
```
Log File:    /var/log/modsentry-audit.log
Format:      timestamp | username | action | ip | rule_id | attack_name | status
Example:     2025-11-09 14:32:15 | root | BLOCK | 203.0.113.45 | 941100 | XSS | Success
```

### Persistent IP Blocks
Blocked IPs are saved and survive system reboots:
```
Config File: /etc/modsentry/blocked-ips.conf
Auto-managed by ModSentry
Restored automatically on startup
```

### Whitelist Configuration
Trusted IP addresses can be configured:
```
Config File: /etc/modsentry/whitelist.conf
Format:      One IP per line, # for comments
Example:
  # Internal networks
  10.0.0.0/8
  172.16.0.0/12
```
## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more details.
