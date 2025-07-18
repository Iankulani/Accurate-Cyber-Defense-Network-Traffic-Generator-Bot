#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Accurate Cyber Defense Security Bot - Network Traffic Generator and Monitor
Version: 7.0
Author: Ian Carter Kulani
"""

import os
import sys
import time
import socket
import threading
import subprocess
import platform
from datetime import datetime
import random
import json
import requests
import argparse
import readline  # For better command line input handling

# Configuration
CONFIG_FILE = "bot_config.json"
DEFAULT_CONFIG = {
    "telegram_token": "",
    "telegram_chat_id": "",
    "monitoring_interval": 60,
    "traffic_generation_duration": 30,
    "max_packets_per_second": 100,
    "default_ports": [80, 443, 22, 3389],
    "log_file": "bot_activity.log"
}

# ANSI color codes for red theme
RED = "\033[91m"
DARK_RED = "\033[31m"
RED_BG = "\033[41m"
RESET = "\033[0m"
BOLD = "\033[1m"

class CyberSecurityBot:
    def __init__(self):
        self.running = False
        self.monitoring_active = False
        self.traffic_generation_active = False
        self.current_target = None
        self.current_port = None
        self.config = self.load_config()
        self.command_history = []
        self.setup_environment()
        
    def setup_environment(self):
        """Set up the environment including logging"""
        if not os.path.exists(CONFIG_FILE):
            self.save_config(DEFAULT_CONFIG)
            
        # Create log file if it doesn't exist
        if not os.path.exists(self.config['log_file']):
            with open(self.config['log_file'], 'w') as f:
                f.write("CyberSecurity Bot Activity Log\n")
                f.write("="*50 + "\n")
                
    def load_config(self):
        """Load configuration from file"""
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                # Merge with default config to ensure all keys exist
                for key in DEFAULT_CONFIG:
                    if key not in config:
                        config[key] = DEFAULT_CONFIG[key]
                return config
        except (FileNotFoundError, json.JSONDecodeError):
            return DEFAULT_CONFIG.copy()
            
    def save_config(self, config):
        """Save configuration to file"""
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
            
    def log_activity(self, message):
        """Log activity to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}"
        
        print(f"{DARK_RED}[LOG]{RESET} {log_entry}")
        with open(self.config['log_file'], 'a') as f:
            f.write(log_entry + "\n")
            
    def send_telegram_message(self, message):
        """Send message to Telegram chat"""
        if not self.config['telegram_token'] or not self.config['telegram_chat_id']:
            self.log_activity("Telegram not configured. Message not sent.")
            return False
            
        url = f"https://api.telegram.org/bot{self.config['telegram_token']}/sendMessage"
        payload = {
            "chat_id": self.config['telegram_chat_id'],
            "text": message,
            "parse_mode": "HTML"
        }
        
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                return True
            else:
                self.log_activity(f"Failed to send Telegram message. Status code: {response.status_code}")
                return False
        except Exception as e:
            self.log_activity(f"Error sending Telegram message: {str(e)}")
            return False
            
    def validate_ip(self, ip):
        """Validate IP address format"""
        try:
            socket.inet_aton(ip)
            return True
        except socket.error:
            return False
            
    def validate_port(self, port):
        """Validate port number"""
        try:
            port = int(port)
            return 1 <= port <= 65535
        except ValueError:
            return False
            
    def ping_ip(self, ip):
        """Ping an IP address"""
        if not self.validate_ip(ip):
            return f"Invalid IP address: {ip}"
            
        param = '-n' if platform.system().lower() == 'windows' else '-c'
        command = ['ping', param, '4', ip]
        
        try:
            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return output
        except subprocess.CalledProcessError as e:
            return e.output
            
    def generate_traffic(self, ip, port=None, duration=None, pps=None):
        """Generate network traffic to specified IP and port"""
        if not self.validate_ip(ip):
            return f"Invalid IP address: {ip}"
            
        if port and not self.validate_port(port):
            return f"Invalid port: {port}"
            
        if not port:
            port = random.choice(self.config['default_ports'])
            
        if not duration:
            duration = self.config['traffic_generation_duration']
            
        if not pps:
            pps = self.config['max_packets_per_second']
            
        self.current_target = ip
        self.current_port = port
        self.traffic_generation_active = True
        
        message = f"Starting traffic generation to {ip}:{port} for {duration} seconds at {pps} packets/sec"
        self.log_activity(message)
        self.send_telegram_message(f"<b>Traffic Generation Started</b>\n{message}")
        
        def traffic_thread():
            start_time = time.time()
            packet_count = 0
            
            while (time.time() - start_time) < duration and self.traffic_generation_active:
                try:
                    # Create a TCP socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1)
                    
                    # Try to connect to the target
                    s.connect((ip, port))
                    packet_count += 1
                    
                    # Send some random data
                    s.send(os.urandom(1024))
                    s.close()
                    
                    # Sleep to control packet rate
                    time.sleep(1/pps)
                    
                except Exception as e:
                    self.log_activity(f"Error generating traffic: {str(e)}")
                    time.sleep(1)
                    
            self.traffic_generation_active = False
            self.current_target = None
            self.current_port = None
            
            stats = f"Traffic generation completed. Sent {packet_count} packets to {ip}:{port}"
            self.log_activity(stats)
            self.send_telegram_message(f"<b>Traffic Generation Complete</b>\n{stats}")
            
        threading.Thread(target=traffic_thread, daemon=True).start()
        return f"Started traffic generation to {ip}:{port}"
        
    def stop_traffic(self):
        """Stop traffic generation"""
        if self.traffic_generation_active:
            self.traffic_generation_active = False
            message = f"Stopped traffic generation to {self.current_target}:{self.current_port}"
            self.log_activity(message)
            self.send_telegram_message(f"<b>Traffic Generation Stopped</b>\n{message}")
            return message
        return "No active traffic generation to stop"
        
    def start_monitoring(self, ip):
        """Start monitoring an IP address"""
        if not self.validate_ip(ip):
            return f"Invalid IP address: {ip}"
            
        if self.monitoring_active:
            return "Monitoring is already active. Stop current monitoring first."
            
        self.monitoring_active = True
        self.current_target = ip
        
        message = f"Starting monitoring of {ip} with interval {self.config['monitoring_interval']} seconds"
        self.log_activity(message)
        self.send_telegram_message(f"<b>Monitoring Started</b>\n{message}")
        
        def monitoring_thread():
            while self.monitoring_active:
                try:
                    # Check if IP is reachable
                    ping_result = self.ping_ip(ip)
                    online = "unreachable" not in ping_result.lower()
                    
                    # Check common ports
                    port_status = {}
                    for port in self.config['default_ports']:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            s.settimeout(1)
                            result = s.connect_ex((ip, port))
                            port_status[port] = "open" if result == 0 else "closed"
                            s.close()
                        except Exception:
                            port_status[port] = "error"
                            
                    # Prepare report
                    status_report = f"Monitoring Report for {ip}:\n"
                    status_report += f"Online: {'Yes' if online else 'No'}\n"
                    status_report += "Port Status:\n"
                    for port, status in port_status.items():
                        status_report += f"  Port {port}: {status}\n"
                        
                    self.log_activity(status_report)
                    self.send_telegram_message(f"<b>Monitoring Update</b>\n{status_report}")
                    
                    # Wait for next interval
                    for _ in range(self.config['monitoring_interval']):
                        if not self.monitoring_active:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    self.log_activity(f"Monitoring error: {str(e)}")
                    time.sleep(self.config['monitoring_interval'])
                    
            self.monitoring_active = False
            self.current_target = None
            message = f"Stopped monitoring of {ip}"
            self.log_activity(message)
            self.send_telegram_message(f"<b>Monitoring Stopped</b>\n{message}")
            
        threading.Thread(target=monitoring_thread, daemon=True).start()
        return f"Started monitoring {ip}"
        
    def stop_monitoring(self):
        """Stop monitoring"""
        if self.monitoring_active:
            self.monitoring_active = False
            return f"Stopping monitoring of {self.current_target}"
        return "No active monitoring to stop"
        
    def clear_screen(self):
        """Clear the terminal screen"""
        os.system('cls' if os.name == 'nt' else 'clear')
        return "Screen cleared"
        
    def show_help(self):
        """Display help information"""
        help_text = f"""
{RED_BG}{BOLD} Accurate Cyber Security Bot - Help Menu {RESET}

{BOLD}Available Commands:{RESET}
  {RED}help{RESET}               - Show this help message
  {RED}exit{RESET}               - Exit the bot
  {RED}clear{RESET}              - Clear the screen
  {RED}ping <IP>{RESET}          - Ping an IP address
  {RED}generate <IP> [port] [duration] [pps]{RESET} - Generate network traffic
  {RED}stop{RESET}               - Stop traffic generation
  {RED}monitor <IP>{RESET}       - Start monitoring an IP address
  {RED}stopmonitor{RESET}        - Stop monitoring
  {RED}config{RESET}             - Show current configuration
  {RED}setconfig <key> <value>{RESET} - Set configuration value
  {RED}history{RESET}            - Show command history
  {RED}status{RESET}             - Show current bot status

{BOLD}Examples:{RESET}
  ping 192.168.1.1
  generate 192.168.1.1 80 60 50
  monitor 8.8.8.8
  setconfig telegram_token YOUR_TOKEN
  setconfig telegram_chat_id YOUR_CHAT_ID
"""
        return help_text
        
    def show_config(self):
        """Display current configuration"""
        config_display = f"{RED_BG}{BOLD} Current Configuration {RESET}\n"
        for key, value in self.config.items():
            if key in ['telegram_token', 'telegram_chat_id'] and value:
                value = value[:3] + "..." + value[-3:]  # Partially hide sensitive info
            config_display += f"{RED}{key}:{RESET} {value}\n"
        return config_display
        
    def set_config(self, key, value):
        """Set configuration value"""
        if key not in DEFAULT_CONFIG:
            return f"Invalid configuration key: {key}"
            
        try:
            # Convert value to appropriate type
            if key in ['monitoring_interval', 'traffic_generation_duration', 'max_packets_per_second']:
                value = int(value)
            elif key == 'default_ports':
                value = [int(p) for p in value.split(',')]
                
            self.config[key] = value
            self.save_config(self.config)
            return f"Configuration updated: {key} = {value}"
        except ValueError:
            return f"Invalid value for {key}. Could not convert to required type."
            
    def show_status(self):
        """Show current bot status"""
        status = f"{RED_BG}{BOLD} Bot Status {RESET}\n"
        status += f"{RED}Running:{RESET} {self.running}\n"
        status += f"{RED}Monitoring:{RESET} {self.monitoring_active}"
        if self.monitoring_active:
            status += f" (Target: {self.current_target})\n"
        else:
            status += "\n"
            
        status += f"{RED}Traffic Generation:{RESET} {self.traffic_generation_active}"
        if self.traffic_generation_active:
            status += f" (Target: {self.current_target}:{self.current_port})\n"
        else:
            status += "\n"
            
        return status
        
    def show_history(self):
        """Show command history"""
        if not self.command_history:
            return "No commands in history"
            
        history_text = f"{RED_BG}{BOLD} Command History {RESET}\n"
        for i, cmd in enumerate(self.command_history[-10:], 1):  # Show last 10 commands
            history_text += f"{i}. {cmd}\n"
        return history_text
        
    def run_command(self, command):
        """Execute a command"""
        self.command_history.append(command)
        parts = command.split()
        if not parts:
            return ""
            
        cmd = parts[0].lower()
        args = parts[1:]
        
        try:
            if cmd == "help":
                return self.show_help()
            elif cmd == "exit":
                self.running = False
                return "Exiting..."
            elif cmd == "clear":
                return self.clear_screen()
            elif cmd == "ping" and len(args) == 1:
                return self.ping_ip(args[0])
            elif cmd == "generate":
                if len(args) == 1:
                    return self.generate_traffic(args[0])
                elif len(args) == 2:
                    return self.generate_traffic(args[0], int(args[1]))
                elif len(args) == 3:
                    return self.generate_traffic(args[0], int(args[1]), int(args[2]))
                elif len(args) == 4:
                    return self.generate_traffic(args[0], int(args[1]), int(args[2]), int(args[3]))
                else:
                    return "Usage: generate <IP> [port] [duration] [pps]"
            elif cmd == "stop":
                return self.stop_traffic()
            elif cmd == "monitor" and len(args) == 1:
                return self.start_monitoring(args[0])
            elif cmd == "stopmonitor":
                return self.stop_monitoring()
            elif cmd == "config":
                return self.show_config()
            elif cmd == "setconfig" and len(args) >= 2:
                return self.set_config(args[0], ' '.join(args[1:]))
            elif cmd == "history":
                return self.show_history()
            elif cmd == "status":
                return self.show_status()
            else:
                return f"Unknown command: {cmd}. Type 'help' for available commands."
        except Exception as e:
            return f"Error executing command: {str(e)}"
            
    def start(self):
        """Start the bot interactive shell"""
        self.running = True
        self.clear_screen()
        
        banner = f"""
{RED_BG}{BOLD}   ACCURATE CYBER DEFENSE SECURITY BOT - NETWORK TRAFFIC GENERATOR   {RESET}
{RED}Version: 1.0{RESET}
{RED}Type 'help' for available commands{RESET}
"""
        print(banner)
        
        while self.running:
            try:
                command = input(f"{DARK_RED}bot>{RESET} ").strip()
                if command:
                    result = self.run_command(command)
                    if result:
                        print(result)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit the bot")
            except EOFError:
                self.running = False
                print("\nExiting...")
                
        # Clean up before exiting
        if self.monitoring_active:
            self.stop_monitoring()
        if self.traffic_generation_active:
            self.stop_traffic()
            
        self.log_activity("Bot stopped")

def main():
    parser = argparse.ArgumentParser(description='Accurate Cyber Security Bot - Network Traffic Generator')
    parser.add_argument('--config', action='store_true', help='Show current configuration')
    parser.add_argument('--set-token', help='Set Telegram bot token')
    parser.add_argument('--set-chatid', help='Set Telegram chat ID')
    args = parser.parse_args()
    
    bot = CyberSecurityBot()
    
    if args.config:
        print(bot.show_config())
        sys.exit(0)
    if args.set_token:
        print(bot.set_config('telegram_token', args.set_token))
        sys.exit(0)
    if args.set_chatid:
        print(bot.set_config('telegram_chat_id', args.set_chatid))
        sys.exit(0)
        
    bot.start()

if __name__ == "__main__":
    main()