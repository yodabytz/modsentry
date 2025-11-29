#!/bin/bash
# Debug monitoring script for modsentry
# Run this in a separate terminal to monitor CPU usage and profiler output

echo "ModSentry Debug Monitor"
echo "===================="
echo ""
echo "This script monitors:"
echo "1. CPU usage of the modsentry process"
echo "2. Profiler output from /tmp/modsentry_debug.log"
echo ""
echo "To use:"
echo "  In terminal 1: sudo python3 /home/snoopy/myapps/modsentry/modsentry.py"
echo "  In terminal 2: bash /home/snoopy/myapps/modsentry/debug_monitor.sh"
echo ""
echo "===================="
echo ""

# Clear the debug log
> /tmp/modsentry_debug.log

echo "Starting debug monitor..."
echo "Press Ctrl+C to stop"
echo ""

while true; do
    clear
    echo "=== CPU Usage ==="
    ps aux | grep modsentry | grep -v grep | awk '{print "PID:", $2, "CPU:", $3"%", "MEM:", $4"%"}'
    echo ""
    echo "=== Recent Profiler Stats ==="
    if [ -f /tmp/modsentry_debug.log ]; then
        tail -20 /tmp/modsentry_debug.log
    else
        echo "No profiler stats yet (waiting for modsentry to run 1000 iterations)..."
    fi
    echo ""
    echo "Last updated: $(date)"
    echo "Press Ctrl+C to stop"
    sleep 5
done
