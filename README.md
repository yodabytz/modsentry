## ModSentry 1.0

ModSentry is a real-time log monitoring tool for analyzing security events from ModSecurity logs. It provides an intuitive terminal interface to track alerts and highlight critical incidents. IP addresses can be blocked or unblocked using `iptables` directly from the interface. For this script to work, ModSecurity must be set to Serial logging.

## Table of Contents

- [Getting Started](#getting-started)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Features](#features)
- [Usage](#usage)
- [Controls](#controls)
- [License](#license)

## Getting Started

These instructions will help you set up and run ModSentry on your local machine for development and testing.

## Requirements

- Python 3.x
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
## Features
Real-time Monitoring: Automatically updates to display new log entries.
Color-Coded Alerts: Quickly identify critical issues with color-coded severity levels.
IP Blocking: Block suspicious IP addresses directly from the interface using iptables.
Popup Confirmation: Confirmation dialogs for blocking IPs and successful actions.
Scrollable Interface: Navigate through logs and detailed views with ease.
Help Command: View usage instructions and controls via the -h switch.

## Usage
Run the application with the following command:
```
sudo modsentry
sudo modsentry -h
```
### Controls
```
Enter: Show more info about the selected entry.
b: Block the IP address of the selected entry.
d: Unblock the IP address of the selected entry
●: Blocked IP
q: Quit the application.
Up/Down Arrows: Navigate through log entries.
Left Arrow/Backspace: Return to the main screen from a detailed view.
```
