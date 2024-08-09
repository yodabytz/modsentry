## ModSentry 1.0

ModSentry is a real-time log monitoring tool for analyzing security events from ModSecurity logs. It provides an intuitive terminal interface to track alerts and highlight critical incidents. For this script to work, modsecurity must be set to Serial logging.

## Table of Contents

- [Getting Started](#getting-started)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

## Getting Started

These instructions will help you set up and run ModSentry on your local machine for development and testing.

## Prerequisites

- Python 3.x
- `curses` library (often included with Python on Unix-based systems)

## Installation

Clone the repository:

```bash
git clone https://github.com/your_username/modsentry.git
cd modsentry
sudo cp modsentry.py /usr/bin/modsentry
```

## Make the Script Executable
```
sudo chmod +x /usr/bin/modsentry
```
## Features

```Real-time Monitoring: Automatically updates to display new log entries.
Color-Coded Alerts: Quickly identify critical issues with color-coded severity levels.
Scrolling Interface: Navigate through logs easily using keyboard input.
Intuitive Display: View logs in a structured, easy-to-read format.
```
## Usage
```Run the application with the following command:
python modsentry.py
```
## License
```
This project is licensed under the MIT License - see the LICENSE file for details.
```
