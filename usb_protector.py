"""
COMPLETE USB SECURITY ALERT SYSTEM - NO WIN32API REQUIRED
With Popup Alerts + Email + Logging + Web Dashboard
"""

import os
import time
import json
import threading
import smtplib
import sqlite3
import ctypes  # For Windows API functions without win32api
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import http.server
import socketserver
import webbrowser
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Check for required modules
try:
    import psutil
    USB_DETECTION_ENABLED = True
except ImportError:
    USB_DETECTION_ENABLED = False
    print("⚠️ Install psutil for USB detection: pip install psutil")

class USBSecuritySystem:
    def __init__(self):
        self.running = False
        self.usb_history = []
        self.alerts_sent = 0
        self.connected_usb = []  # Track connected USB drives
        
        # Configuration
        self.config = self.load_config()
        
        # Database setup
        self.db_setup()
        
        # Start GUI
        self.setup_gui()
        
        # Start monitoring automatically
        self.start_monitoring()
        
        # Start web dashboard
        self.start_web_dashboard()
        
        # Initial status update
        self.update_status()
        
        # Initial USB scan
        self.scan_existing_usb()
    
    def load_config(self):
        """Load or create configuration"""
        config_file = "usb_config.json"
        default_config = {
            "admin_name": "Administrator",
            "admin_email": "your_email@gmail.com",
            "admin_phone": "+1234567890",
            
            # Email settings
            "smtp_server": "smtp.gmail.com",
            "smtp_port": 587,
            "email_username": "your_email@gmail.com",
            "email_password": "your_app_password",
            
            # Alert settings
            "enable_popup": True,
            "enable_email": False,  # Disable by default until configured
            "enable_web": True,
            "web_port": 8080,
            
            # Auto actions
            "auto_scan": True,
            "auto_log": True,
            "notify_on_insert": True,
            "notify_on_remove": True,
            
            # Security settings
            "block_suspicious": False,
            "whitelist_drives": [],
            "blacklist_drives": []
        }
        
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except:
                return default_config
        else:
            with open(config_file, 'w') as f:
                json.dump(default_config, f, indent=4)
            print(f"📄 Created config file: {config_file}")
            print("⚠️  Please edit usb_config.json with your email settings")
            return default_config
    
    def db_setup(self):
        """Setup SQLite database"""
        self.conn = sqlite3.connect('usb_security.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        
        # Create tables
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS usb_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                event_type TEXT,
                drive_letter TEXT,
                drive_label TEXT,
                total_size_gb REAL,
                free_space_gb REAL,
                serial_number TEXT,
                vendor_id TEXT,
                product_id TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                alert_type TEXT,
                message TEXT,
                status TEXT
            )
        ''')
        
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS suspicious_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                drive_letter TEXT,
                file_path TEXT,
                file_name TEXT,
                file_extension TEXT,
                file_size_mb REAL,
                threat_level TEXT
            )
        ''')
        
        self.conn.commit()
        print("✅ Database initialized")
    
    def setup_gui(self):
        """Setup the main GUI window"""
        self.root = tk.Tk()
        self.root.title("🔒 USB Security Monitor v3.0")
        self.root.geometry("1100x750")
        self.root.configure(bg='#f8f9fa')
        
        # Custom style
        style = ttk.Style()
        style.theme_use('clam')
        
        # Title Bar
        title_frame = tk.Frame(self.root, bg='#1a237e', height=90)
        title_frame.pack(fill='x')
        title_frame.pack_propagate(False)
        
        tk.Label(title_frame, text="🔐 USB SECURITY MONITOR", 
                font=('Segoe UI', 28, 'bold'), bg='#1a237e', fg='white').pack(pady=25)
        
        # Control Panel
        control_frame = tk.Frame(self.root, bg='white', relief=tk.RAISED, borderwidth=1)
        control_frame.pack(fill='x', padx=15, pady=10)
        
        # Status Panel
        status_panel = tk.Frame(control_frame, bg='white')
        status_panel.pack(side='left', padx=20, pady=10)
        
        # System Status
        tk.Label(status_panel, text="SYSTEM STATUS", font=('Segoe UI', 10, 'bold'),
                fg='#5d4037', bg='white').pack(anchor='w')
        
        self.status_label = tk.Label(status_panel, text="● STOPPED", 
                                    font=('Segoe UI', 14, 'bold'), fg='#f44336', bg='white')
        self.status_label.pack(anchor='w')
        
        # Connected USB Count
        usb_frame = tk.Frame(control_frame, bg='white')
        usb_frame.pack(side='left', padx=40, pady=10)
        
        tk.Label(usb_frame, text="CONNECTED USB", font=('Segoe UI', 10, 'bold'),
                fg='#5d4037', bg='white').pack(anchor='w')
        
        self.usb_count_label = tk.Label(usb_frame, text="0", 
                                       font=('Segoe UI', 20, 'bold'), fg='#2196f3', bg='white')
        self.usb_count_label.pack(anchor='w')
        
        # Alert Count
        alert_frame = tk.Frame(control_frame, bg='white')
        alert_frame.pack(side='left', padx=40, pady=10)
        
        tk.Label(alert_frame, text="TOTAL ALERTS", font=('Segoe UI', 10, 'bold'),
                fg='#5d4037', bg='white').pack(anchor='w')
        
        self.alert_count_label = tk.Label(alert_frame, text="0", 
                                         font=('Segoe UI', 20, 'bold'), fg='#ff5722', bg='white')
        self.alert_count_label.pack(anchor='w')
        
        # Threat Count
        threat_frame = tk.Frame(control_frame, bg='white')
        threat_frame.pack(side='left', padx=40, pady=10)
        
        tk.Label(threat_frame, text="THREATS FOUND", font=('Segoe UI', 10, 'bold'),
                fg='#5d4037', bg='white').pack(anchor='w')
        
        self.threat_count_label = tk.Label(threat_frame, text="0", 
                                          font=('Segoe UI', 20, 'bold'), fg='#d32f2f', bg='white')
        self.threat_count_label.pack(anchor='w')
        
        # Control Buttons (Right side)
        button_frame = tk.Frame(control_frame, bg='white')
        button_frame.pack(side='right', padx=20, pady=10)
        
        # Create a grid for buttons
        btn_grid = tk.Frame(button_frame, bg='white')
        btn_grid.pack()
        
        buttons = [
            ("▶ Start", '#4caf50', self.start_monitoring, 0, 0),
            ("⏹ Stop", '#f44336', self.stop_monitoring, 0, 1),
            ("⚙️ Settings", '#2196f3', self.open_settings, 1, 0),
            ("📊 Logs", '#ff9800', self.view_logs, 1, 1),
            ("📧 Test Email", '#9c27b0', self.test_email, 2, 0),
            ("🔍 Scan Now", '#009688', self.scan_all_usb, 2, 1),
            ("🔄 Refresh", '#607d8b', self.refresh_display, 3, 0),
            ("🌐 Dashboard", '#795548', self.open_web_dashboard, 3, 1)
        ]
        
        for text, color, command, row, col in buttons:
            btn = tk.Button(btn_grid, text=text, font=('Segoe UI', 10, 'bold'),
                          bg=color, fg='white', width=12, height=2,
                          command=command, relief='flat')
            btn.grid(row=row, column=col, padx=2, pady=2)
        
        # Main Content Area
        main_frame = tk.Frame(self.root, bg='white')
        main_frame.pack(fill='both', expand=True, padx=15, pady=10)
        
        # Left Panel - Current USB Devices
        left_frame = tk.LabelFrame(main_frame, text=" 🔌 CONNECTED USB DEVICES ", 
                                  font=('Segoe UI', 12, 'bold'), bg='white', fg='#1a237e')
        left_frame.pack(side='left', fill='both', expand=True, padx=(0, 10))
        
        # Treeview for USB devices with style
        columns = ('Drive', 'Label', 'Type', 'Size', 'Free', 'Status')
        self.usb_tree = ttk.Treeview(left_frame, columns=columns, show='headings', height=12)
        
        # Configure columns
        col_widths = {'Drive': 80, 'Label': 120, 'Type': 100, 'Size': 80, 'Free': 80, 'Status': 100}
        for col in columns:
            self.usb_tree.heading(col, text=col, anchor='w')
            self.usb_tree.column(col, width=col_widths.get(col, 100), anchor='w')
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(left_frame, orient='vertical', command=self.usb_tree.yview)
        self.usb_tree.configure(yscrollcommand=scrollbar.set)
        
        self.usb_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Right Panel - Real-time Log
        right_frame = tk.LabelFrame(main_frame, text=" 📝 REAL-TIME EVENT LOG ", 
                                   font=('Segoe UI', 12, 'bold'), bg='white', fg='#1a237e')
        right_frame.pack(side='right', fill='both', expand=True, padx=(10, 0))
        
        # Log text area with custom colors
        self.log_text = scrolledtext.ScrolledText(right_frame, height=15, 
                                                 font=('Consolas', 10),
                                                 bg='#0d1117', fg='#c9d1d9')
        self.log_text.pack(fill='both', expand=True, padx=10, pady=10)
        self.log_text.insert('end', f"[{datetime.now().strftime('%H:%M:%S')}] System initialized\n")
        self.log_text.config(state='disabled')
        
        # Alert History Panel
        alert_history_frame = tk.LabelFrame(self.root, text=" 🚨 RECENT ALERTS ", 
                                          font=('Segoe UI', 12, 'bold'), bg='white', fg='#b71c1c')
        alert_history_frame.pack(fill='x', padx=15, pady=(0, 15))
        
        alert_columns = ('Time', 'Type', 'Device', 'Message', 'Action')
        self.alert_tree = ttk.Treeview(alert_history_frame, columns=alert_columns, 
                                       show='headings', height=6)
        
        col_widths = {'Time': 120, 'Type': 100, 'Device': 100, 'Message': 350, 'Action': 100}
        for col in alert_columns:
            self.alert_tree.heading(col, text=col, anchor='w')
            self.alert_tree.column(col, width=col_widths.get(col, 100), anchor='w')
        
        alert_scrollbar = ttk.Scrollbar(alert_history_frame, orient='vertical', 
                                       command=self.alert_tree.yview)
        self.alert_tree.configure(yscrollcommand=alert_scrollbar.set)
        
        self.alert_tree.pack(side='left', fill='both', expand=True)
        alert_scrollbar.pack(side='right', fill='y')
        
        # Status Bar (Footer)
        footer_frame = tk.Frame(self.root, bg='#1a237e', height=40)
        footer_frame.pack(fill='x', side='bottom')
        footer_frame.pack_propagate(False)
        
        self.footer_label = tk.Label(footer_frame, 
                                    text="System Ready | Monitoring: OFF | Last Update: --:--:--", 
                                    font=('Segoe UI', 10), bg='#1a237e', fg='white')
        self.footer_label.pack(pady=10)
        
        # Update initial counts
        self.update_counts()
        
        print("✅ GUI initialized successfully")
    
    def log_message(self, message, alert=False, level="INFO"):
        """Add message to log with color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on level
        colors = {
            "INFO": "#58a6ff",
            "WARN": "#f0883e",
            "ERROR": "#f85149",
            "ALERT": "#ff6b6b",
            "SUCCESS": "#3fb950"
        }
        
        color = colors.get(level, "#c9d1d9")
        log_entry = f"[{timestamp}] {message}\n"
        
        # Update log text with color
        self.log_text.config(state='normal')
        self.log_text.insert('end', log_entry)
        
        # Apply color to the last line
        start_index = f"end-{len(log_entry)}c"
        end_index = "end-1c"
        self.log_text.tag_add(level, start_index, end_index)
        self.log_text.tag_config(level, foreground=color)
        
        self.log_text.see('end')
        self.log_text.config(state='disabled')
        
        # Print to console
        print(f"[{level}] {log_entry.strip()}")
        
        # Update footer timestamp
        self.update_footer_timestamp()
        
        # If alert, trigger alert actions
        if alert:
            self.trigger_alert(message, level)
    
    def trigger_alert(self, message, level="ALERT"):
        """Trigger alert actions"""
        self.alerts_sent += 1
        
        # Update alert count
        self.alert_count_label.config(text=str(self.alerts_sent))
        
        # Show popup alert
        if self.config.get('enable_popup', True):
            self.show_popup_alert(message, level)
        
        # Send email alert if enabled
        if self.config.get('enable_email', False):
            self.send_email_alert(message, level)
        
        # Log to database
        self.log_alert_to_db(message, level)
        
        # Update footer
        self.update_footer()
    
    def show_popup_alert(self, message, level="ALERT"):
        """Show popup alert window"""
        # Map level to colors and icons
        level_config = {
            "ALERT": {"color": "#d32f2f", "icon": "🚨", "title": "SECURITY ALERT"},
            "WARN": {"color": "#f57c00", "icon": "⚠️", "title": "WARNING"},
            "ERROR": {"color": "#c2185b", "icon": "❌", "title": "ERROR"},
            "INFO": {"color": "#1976d2", "icon": "ℹ️", "title": "INFORMATION"}
        }
        
        config = level_config.get(level, level_config["ALERT"])
        
        alert_window = tk.Toplevel(self.root)
        alert_window.title(f"{config['icon']} USB {config['title']}")
        alert_window.geometry("500x350")
        alert_window.configure(bg=config['color'])
        alert_window.attributes('-topmost', True)
        
        # Make window stay on top
        alert_window.lift()
        alert_window.focus_force()
        
        # Header
        header_frame = tk.Frame(alert_window, bg=config['color'], height=80)
        header_frame.pack(fill='x')
        header_frame.pack_propagate(False)
        
        tk.Label(header_frame, text=config['icon'], font=('Arial', 36), 
                bg=config['color'], fg='white').pack(pady=10)
        
        tk.Label(header_frame, text=config['title'], font=('Arial', 18, 'bold'), 
                bg=config['color'], fg='white').pack()
        
        # Content
        content_frame = tk.Frame(alert_window, bg='white')
        content_frame.pack(fill='both', expand=True, padx=2, pady=(0, 2))
        
        # Message
        tk.Label(content_frame, text=message, font=('Arial', 12), 
                bg='white', wraplength=450, justify='left').pack(pady=30, padx=20)
        
        # Time
        tk.Label(content_frame, text=f"Time: {datetime.now().strftime('%H:%M:%S')}", 
                font=('Arial', 10), bg='white', fg='#666').pack()
        
        # Buttons
        button_frame = tk.Frame(content_frame, bg='white')
        button_frame.pack(pady=20)
        
        tk.Button(button_frame, text="ACKNOWLEDGE", bg=config['color'], fg='white',
                 font=('Arial', 11, 'bold'), width=15,
                 command=alert_window.destroy).pack(side='left', padx=10)
        
        tk.Button(button_frame, text="VIEW DETAILS", bg='#555', fg='white',
                 font=('Arial', 11), width=15,
                 command=lambda: [alert_window.destroy(), self.view_logs()]).pack(side='left', padx=10)
        
        # Auto-close after 30 seconds
        alert_window.after(30000, alert_window.destroy)
        
        # Make sound (Windows)
        try:
            import winsound
            frequency = 1000  # Hz
            duration = 1000  # ms
            winsound.Beep(frequency, duration)
        except:
            pass
    
    def send_email_alert(self, message, level="ALERT"):
        """Send email alert"""
        try:
            smtp_server = self.config.get('smtp_server', 'smtp.gmail.com')
            smtp_port = self.config.get('smtp_port', 587)
            username = self.config.get('email_username')
            password = self.config.get('email_password')
            to_email = self.config.get('admin_email')
            
            if not all([username, password, to_email]):
                self.log_message("⚠️ Email not configured properly", False, "WARN")
                return False
            
            if username == 'your_email@gmail.com':
                self.log_message("⚠️ Please update email configuration in settings", False, "WARN")
                return False
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = username
            msg['To'] = to_email
            msg['Subject'] = f"{level}: USB Security Alert - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px;">
                <div style="background-color: {'#ff4444' if level == 'ALERT' else '#ff9800'}; 
                          color: white; padding: 25px; border-radius: 10px;">
                    <h2>{'🚨' if level == 'ALERT' else '⚠️'} USB SECURITY {level}</h2>
                    <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    <p><strong>System:</strong> {os.environ.get('COMPUTERNAME', 'Unknown PC')}</p>
                    <hr style="border-color: white;">
                    <div style="background-color: rgba(255,255,255,0.1); padding: 15px; border-radius: 5px;">
                        <p style="font-size: 16px;"><strong>Alert Message:</strong></p>
                        <p>{message}</p>
                    </div>
                </div>
                <p style="color: #666; margin-top: 20px;">
                    <em>This is an automated alert from USB Security Monitor v3.0</em>
                </p>
            </body>
            </html>
            """
            
            msg.attach(MIMEText(body, 'html'))
            
            # Send email
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                server.starttls()
                server.login(username, password)
                server.send_message(msg)
            
            self.log_message(f"📧 Email sent to {to_email}", False, "SUCCESS")
            return True
            
        except Exception as e:
            self.log_message(f"❌ Email failed: {str(e)}", False, "ERROR")
            return False
    
    def log_alert_to_db(self, message, level="ALERT"):
        """Log alert to database"""
        try:
            timestamp = datetime.now().isoformat()
            self.cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, message, status)
                VALUES (?, ?, ?, ?)
            ''', (timestamp, level, message, 'Sent'))
            self.conn.commit()
            
            # Add to alert tree
            device = "Unknown"
            if "USB" in message:
                # Extract drive letter from message if present
                import re
                match = re.search(r'[A-Z]:', message)
                if match:
                    device = match.group(0)
            
            self.alert_tree.insert('', 'end', values=(
                datetime.now().strftime("%H:%M:%S"),
                level,
                device,
                message[:50] + "..." if len(message) > 50 else message,
                "View"
            ))
            
            # Keep only last 30 alerts in tree
            if len(self.alert_tree.get_children()) > 30:
                self.alert_tree.delete(self.alert_tree.get_children()[0])
                
        except Exception as e:
            self.log_message(f"Database error: {e}", False, "ERROR")
    
    def get_drive_info(self, drive_path):
        """Get information about a drive without win32api"""
        try:
            drive = drive_path.replace('\\', '')
            label = "Unknown"
            total_size = 0
            free_space = 0
            
            # Try to get size info using psutil
            if USB_DETECTION_ENABLED:
                try:
                    usage = psutil.disk_usage(drive_path)
                    total_size = round(usage.total / (1024**3), 2)  # Convert to GB
                    free_space = round(usage.free / (1024**3), 2)
                except:
                    pass
            
            # Try to get label using ctypes (Windows only)
            if os.name == 'nt':
                try:
                    # Windows API for volume name
                    kernel32 = ctypes.windll.kernel32
                    volume_name_buffer = ctypes.create_unicode_buffer(1024)
                    file_system_buffer = ctypes.create_unicode_buffer(1024)
                    
                    success = kernel32.GetVolumeInformationW(
                        ctypes.c_wchar_p(drive_path),
                        volume_name_buffer,
                        ctypes.sizeof(volume_name_buffer),
                        None,
                        None,
                        None,
                        file_system_buffer,
                        ctypes.sizeof(file_system_buffer)
                    )
                    
                    if success and volume_name_buffer.value:
                        label = volume_name_buffer.value
                except:
                    pass
            
            # If no label found, create a default one
            if label == "Unknown" or not label:
                # Check if it's a system drive
                if drive_path.lower().startswith('c:'):
                    label = "System Drive"
                else:
                    label = f"USB Drive ({drive})"
            
            return {
                'drive': drive,
                'label': label,
                'total_gb': total_size,
                'free_gb': free_space,
                'used_percent': round((total_size - free_space) / total_size * 100, 1) if total_size > 0 else 0
            }
            
        except Exception as e:
            return {
                'drive': drive_path.replace('\\', ''),
                'label': "Error",
                'total_gb': 0,
                'free_gb': 0,
                'used_percent': 0
            }
    
    def detect_usb_devices(self):
        """Main USB detection loop"""
        previous_drives = []
        
        while self.running:
            try:
                current_drives = []
                
                if USB_DETECTION_ENABLED:
                    # Get all disk partitions
                    for partition in psutil.disk_partitions():
                        try:
                            # Check if it's a removable drive
                            if 'removable' in partition.opts.lower():
                                drive = partition.device
                                mountpoint = partition.mountpoint
                                
                                current_drives.append(drive)
                                self.connected_usb.append(drive)
                                
                                # Check if this is a new USB
                                if drive not in previous_drives:
                                    self.handle_usb_inserted(drive, mountpoint)
                                    
                        except Exception as e:
                            continue
                
                # Check for removed USB drives
                for drive in previous_drives:
                    if drive not in current_drives:
                        if drive in self.connected_usb:
                            self.connected_usb.remove(drive)
                        self.handle_usb_removed(drive)
                
                # Update display
                self.update_usb_display(current_drives)
                
                previous_drives = current_drives
                
                # Update counts every iteration
                self.update_counts()
                
                # Sleep for 2 seconds
                time.sleep(2)
                
            except Exception as e:
                self.log_message(f"Detection error: {str(e)}", False, "ERROR")
                time.sleep(5)
    
    def handle_usb_inserted(self, drive, mountpoint):
        """Handle USB insertion event"""
        try:
            # Get drive information
            drive_info = self.get_drive_info(mountpoint)
            
            # Create event message
            size_info = ""
            if drive_info['total_gb'] > 0:
                size_info = f" - Size: {drive_info['total_gb']}GB ({drive_info['free_gb']}GB free)"
            
            event_msg = f"📌 USB INSERTED: {drive} ({drive_info['label']}){size_info}"
            
            # Log event
            should_alert = self.config.get('notify_on_insert', True)
            self.log_message(event_msg, alert=should_alert, level="ALERT")
            
            # Log to database
            timestamp = datetime.now().isoformat()
            self.cursor.execute('''
                INSERT INTO usb_events (timestamp, event_type, drive_letter, drive_label, total_size_gb, free_space_gb)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (timestamp, 'INSERTED', drive, drive_info['label'], 
                  drive_info['total_gb'], drive_info['free_gb']))
            self.conn.commit()
            
            # Auto-scan if enabled
            if self.config.get('auto_scan', True):
                # Don't scan system drives
                if not drive.lower().startswith('c:'):
                    self.scan_usb(mountpoint)
            
        except Exception as e:
            self.log_message(f"Error handling USB insertion: {str(e)}", False, "ERROR")
    
    def handle_usb_removed(self, drive):
        """Handle USB removal event"""
        event_msg = f"📌 USB REMOVED: {drive}"
        
        # Log event
        should_alert = self.config.get('notify_on_remove', True)
        self.log_message(event_msg, alert=should_alert, level="INFO")
        
        # Log to database
        timestamp = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT INTO usb_events (timestamp, event_type, drive_letter)
            VALUES (?, ?, ?)
        ''', (timestamp, 'REMOVED', drive))
        self.conn.commit()
    
    def scan_existing_usb(self):
        """Scan for already connected USB devices on startup"""
        if not USB_DETECTION_ENABLED:
            return
        
        try:
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts.lower():
                    drive = partition.device
                    mountpoint = partition.mountpoint
                    
                    if drive not in self.connected_usb:
                        self.connected_usb.append(drive)
                        
                        drive_info = self.get_drive_info(mountpoint)
                        event_msg = f"📌 Found existing USB: {drive} ({drive_info['label']})"
                        self.log_message(event_msg, False, "INFO")
                        
                        # Add to database
                        timestamp = datetime.now().isoformat()
                        self.cursor.execute('''
                            INSERT INTO usb_events (timestamp, event_type, drive_letter, drive_label)
                            VALUES (?, ?, ?, ?)
                        ''', (timestamp, 'FOUND', drive, drive_info['label']))
                        self.conn.commit()
        except Exception as e:
            self.log_message(f"Error scanning existing USB: {str(e)}", False, "ERROR")
    
    def scan_usb(self, path):
        """Scan USB for suspicious files"""
        self.log_message(f"🔍 Scanning USB: {path}", False, "INFO")
        
        suspicious_ext = ['.exe', '.bat', '.cmd', '.vbs', '.ps1', '.js', '.scr', 
                         '.dll', '.sys', '.msi', '.pif', '.com', '.jar']
        
        threats_found = 0
        
        try:
            for root, dirs, files in os.walk(path, topdown=True):
                for file in files:
                    file_ext = os.path.splitext(file)[1].lower()
                    
                    if file_ext in suspicious_ext:
                        threats_found += 1
                        file_path = os.path.join(root, file)
                        
                        # Get file size
                        try:
                            file_size = os.path.getsize(file_path) / (1024 * 1024)  # Convert to MB
                        except:
                            file_size = 0
                        
                        # Determine threat level
                        if file_ext in ['.exe', '.bat', '.vbs', '.ps1']:
                            threat_level = "HIGH"
                        else:
                            threat_level = "MEDIUM"
                        
                        # Log threat
                        threat_msg = f"⚠️ {threat_level} threat: {file} ({file_ext})"
                        self.log_message(threat_msg, alert=True, level="WARN")
                        
                        # Log to database
                        timestamp = datetime.now().isoformat()
                        drive_letter = path[:2] if len(path) >= 2 else "Unknown"
                        self.cursor.execute('''
                            INSERT INTO suspicious_files 
                            (timestamp, drive_letter, file_path, file_name, file_extension, file_size_mb, threat_level)
                            VALUES (?, ?, ?, ?, ?, ?, ?)
                        ''', (timestamp, drive_letter, file_path, file, file_ext, 
                              round(file_size, 2), threat_level))
                        self.conn.commit()
                
                # Limit depth to avoid long scans
                dirs[:] = dirs[:3]  # Only scan first 3 directories at each level
                
            # Summary
            if threats_found > 0:
                alert_msg = f"🚨 SCAN COMPLETE: Found {threats_found} suspicious files!"
                self.log_message(alert_msg, alert=True, level="ALERT")
                self.threat_count_label.config(text=str(threats_found))
            else:
                self.log_message("✅ Scan complete: No threats found", False, "SUCCESS")
                
        except PermissionError:
            self.log_message("❌ Permission denied for scanning", False, "ERROR")
        except Exception as e:
            self.log_message(f"❌ Scan error: {str(e)}", False, "ERROR")
    
    def scan_all_usb(self):
        """Scan all connected USB drives"""
        self.log_message("🔍 Scanning all connected USB drives...", False, "INFO")
        
        if not self.connected_usb:
            self.log_message("No USB drives connected to scan", False, "INFO")
            return
        
        for drive in self.connected_usb:
            try:
                # Get mountpoint from drive letter
                for partition in psutil.disk_partitions():
                    if partition.device.lower() == drive.lower():
                        self.scan_usb(partition.mountpoint)
                        break
            except:
                continue
    
    def update_usb_display(self, usb_drives):
        """Update USB treeview with current drives"""
        # Clear current items
        for item in self.usb_tree.get_children():
            self.usb_tree.delete(item)
        
        # Add current USB drives
        for drive in usb_drives:
            try:
                # Get mountpoint
                mountpoint = drive
                for partition in psutil.disk_partitions():
                    if partition.device == drive:
                        mountpoint = partition.mountpoint
                        break
                
                # Get drive info
                drive_info = self.get_drive_info(mountpoint)
                
                # Determine status
                status = "✅ Safe"
                if drive_info['free_gb'] == 0:
                    status = "⚠️ Full"
                elif drive_info['used_percent'] > 90:
                    status = "⚠️ Almost Full"
                
                # Add to tree
                self.usb_tree.insert('', 'end', values=(
                    drive_info['drive'],
                    drive_info['label'],
                    "Removable",
                    f"{drive_info['total_gb']} GB",
                    f"{drive_info['free_gb']} GB",
                    status
                ))
                
            except Exception as e:
                self.usb_tree.insert('', 'end', values=(drive, "Error", "Unknown", "?", "?", "❌ Error"))
    
    def update_counts(self):
        """Update all counters"""
        try:
            # Update USB count
            usb_count = len(self.connected_usb)
            self.usb_count_label.config(text=str(usb_count))
            
            # Update alert count from database
            self.cursor.execute('SELECT COUNT(*) FROM alerts')
            alert_count = self.cursor.fetchone()[0]
            self.alert_count_label.config(text=str(alert_count))
            
            # Update threat count
            self.cursor.execute('SELECT COUNT(*) FROM suspicious_files')
            threat_count = self.cursor.fetchone()[0]
            self.threat_count_label.config(text=str(threat_count))
            
        except Exception as e:
            print(f"Error updating counts: {e}")
    
    def update_footer(self):
        """Update footer information"""
        try:
            self.cursor.execute('SELECT COUNT(*) FROM usb_events')
            total_events = self.cursor.fetchone()[0]
            
            status = "RUNNING" if self.running else "STOPPED"
            connected = len(self.connected_usb)
            
            self.footer_label.config(
                text=f"Status: {status} | Connected USB: {connected} | Total Events: {total_events} | Last Update: {datetime.now().strftime('%H:%M:%S')}"
            )
        except:
            pass
    
    def update_footer_timestamp(self):
        """Update just the timestamp in footer"""
        current_text = self.footer_label.cget("text")
        if "Last Update:" in current_text:
            parts = current_text.split("|")
            if len(parts) >= 4:
                parts[-1] = f" Last Update: {datetime.now().strftime('%H:%M:%S')}"
                new_text = "|".join(parts)
                self.footer_label.config(text=new_text)
    
    def update_status(self):
        """Update status label"""
        if self.running:
            self.status_label.config(text="● RUNNING", fg='#4caf50')
        else:
            self.status_label.config(text="● STOPPED", fg='#f44336')
    
    def start_monitoring(self):
        """Start USB monitoring"""
        if not self.running:
            self.running = True
            self.update_status()
            self.log_message("✅ Monitoring STARTED", False, "SUCCESS")
            
            # Start detection thread
            self.monitor_thread = threading.Thread(target=self.detect_usb_devices, daemon=True)
            self.monitor_thread.start()
            
            self.update_footer()
    
    def stop_monitoring(self):
        """Stop USB monitoring"""
        if self.running:
            self.running = False
            self.update_status()
            self.log_message("🛑 Monitoring STOPPED", False, "INFO")
            self.update_footer()
    
    def open_settings(self):
        """Open settings window"""
        settings_window = tk.Toplevel(self.root)
        settings_window.title("Settings")
        settings_window.geometry("700x600")
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # Create notebook for tabs
        notebook = ttk.Notebook(settings_window)
        
        # General Settings Tab
        general_frame = ttk.Frame(notebook)
        
        tk.Label(general_frame, text="General Settings", 
                font=('Segoe UI', 16, 'bold')).pack(pady=20)
        
        # Alert Settings Frame
        alert_frame = tk.LabelFrame(general_frame, text="Alert Settings", 
                                   font=('Segoe UI', 12, 'bold'), padx=20, pady=15)
        alert_frame.pack(fill='x', padx=20, pady=10)
        
        self.popup_var = tk.BooleanVar(value=self.config.get('enable_popup', True))
        tk.Checkbutton(alert_frame, text="Enable Popup Alerts", 
                      variable=self.popup_var, font=('Segoe UI', 11)).pack(anchor='w', pady=5)
        
        self.email_var = tk.BooleanVar(value=self.config.get('enable_email', False))
        tk.Checkbutton(alert_frame, text="Enable Email Alerts", 
                      variable=self.email_var, font=('Segoe UI', 11)).pack(anchor='w', pady=5)
        
        self.scan_var = tk.BooleanVar(value=self.config.get('auto_scan', True))
        tk.Checkbutton(alert_frame, text="Auto-scan USB on insertion", 
                      variable=self.scan_var, font=('Segoe UI', 11)).pack(anchor='w', pady=5)
        
        # Notification Settings Frame
        notify_frame = tk.LabelFrame(general_frame, text="Notification Settings", 
                                    font=('Segoe UI', 12, 'bold'), padx=20, pady=15)
        notify_frame.pack(fill='x', padx=20, pady=10)
        
        self.notify_insert_var = tk.BooleanVar(value=self.config.get('notify_on_insert', True))
        tk.Checkbutton(notify_frame, text="Notify on USB insertion", 
                      variable=self.notify_insert_var, font=('Segoe UI', 11)).pack(anchor='w', pady=5)
        
        self.notify_remove_var = tk.BooleanVar(value=self.config.get('notify_on_remove', True))
        tk.Checkbutton(notify_frame, text="Notify on USB removal", 
                      variable=self.notify_remove_var, font=('Segoe UI', 11)).pack(anchor='w', pady=5)
        
        notebook.add(general_frame, text="General")
        
        # Email Settings Tab
        email_frame = ttk.Frame(notebook)
        
        tk.Label(email_frame, text="Email Configuration", 
                font=('Segoe UI', 16, 'bold')).pack(pady=20)
        
        # Email fields
        fields = [
            ("SMTP Server:", "smtp_server", "smtp.gmail.com"),
            ("SMTP Port:", "smtp_port", "587"),
            ("Username/Email:", "email_username", "your_email@gmail.com"),
            ("Password/App Password:", "email_password", ""),
            ("Admin Email:", "admin_email", "admin@example.com")
        ]
        
        self.email_entries = {}
        for label, key, default in fields:
            frame = tk.Frame(email_frame)
            frame.pack(fill='x', padx=40, pady=8)
            
            tk.Label(frame, text=label, font=('Segoe UI', 11), width=25, anchor='w').pack(side='left')
            entry = tk.Entry(frame, font=('Segoe UI', 11), width=30)
            entry.pack(side='left', padx=(10, 0))
            entry.insert(0, self.config.get(key, default))
            self.email_entries[key] = entry
        
        # Help text
        help_text = """
        For Gmail users:
        • Use your full email address as username
        • Use App Password (not regular password)
        • Enable 2-factor authentication first
        • Generate app password from Google Account settings
        """
        
        help_label = tk.Label(email_frame, text=help_text, font=('Segoe UI', 10),
                             fg='#666', justify='left', wraplength=500)
        help_label.pack(pady=20, padx=40)
        
        notebook.add(email_frame, text="Email")
        
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Save and Cancel buttons
        button_frame = tk.Frame(settings_window)
        button_frame.pack(pady=20)
        
        def save_settings():
            # Update config from variables
            self.config['enable_popup'] = self.popup_var.get()
            self.config['enable_email'] = self.email_var.get()
            self.config['auto_scan'] = self.scan_var.get()
            self.config['notify_on_insert'] = self.notify_insert_var.get()
            self.config['notify_on_remove'] = self.notify_remove_var.get()
            
            # Update config from entries
            for key, entry in self.email_entries.items():
                self.config[key] = entry.get()
            
            # Save to file
            with open('usb_config.json', 'w') as f:
                json.dump(self.config, f, indent=4)
            
            self.log_message("Settings saved successfully", False, "SUCCESS")
            settings_window.destroy()
        
        tk.Button(button_frame, text="💾 Save Settings", font=('Segoe UI', 11, 'bold'),
                 bg='#4caf50', fg='white', width=15, command=save_settings).pack(side='left', padx=10)
        
        tk.Button(button_frame, text="❌ Cancel", font=('Segoe UI', 11),
                 bg='#f44336', fg='white', width=15,
                 command=settings_window.destroy).pack(side='left', padx=10)
    
    def view_logs(self):
        """View detailed logs"""
        log_window = tk.Toplevel(self.root)
        log_window.title("Event Logs & Reports")
        log_window.geometry("1000x700")
        
        # Create notebook
        notebook = ttk.Notebook(log_window)
        
        # USB Events Tab
        usb_frame = ttk.Frame(notebook)
        
        columns = ('ID', 'Time', 'Event', 'Drive', 'Label', 'Size', 'Free')
        usb_tree = ttk.Treeview(usb_frame, columns=columns, show='headings', height=20)
        
        for col in columns:
            usb_tree.heading(col, text=col)
        
        # Load data
        self.cursor.execute('SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT 200')
        for event in self.cursor.fetchall():
            usb_tree.insert('', 'end', values=event[:7])
        
        scrollbar = ttk.Scrollbar(usb_frame, orient='vertical', command=usb_tree.yview)
        usb_tree.configure(yscrollcommand=scrollbar.set)
        
        usb_tree.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Alerts Tab
        alert_frame = ttk.Frame(notebook)
        
        alert_columns = ('ID', 'Time', 'Type', 'Message', 'Status')
        alert_tree = ttk.Treeview(alert_frame, columns=alert_columns, show='headings', height=20)
        
        for col in alert_columns:
            alert_tree.heading(col, text=col)
        
        # Load data
        self.cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200')
        for alert in self.cursor.fetchall():
            alert_tree.insert('', 'end', values=alert[:5])
        
        alert_scrollbar = ttk.Scrollbar(alert_frame, orient='vertical', command=alert_tree.yview)
        alert_tree.configure(yscrollcommand=alert_scrollbar.set)
        
        alert_tree.pack(side='left', fill='both', expand=True)
        alert_scrollbar.pack(side='right', fill='y')
        
        # Threats Tab
        threat_frame = ttk.Frame(notebook)
        
        threat_columns = ('ID', 'Time', 'Drive', 'File', 'Extension', 'Size', 'Threat Level')
        threat_tree = ttk.Treeview(threat_frame, columns=threat_columns, show='headings', height=20)
        
        for col in threat_columns:
            threat_tree.heading(col, text=col)
        
        # Load data
        self.cursor.execute('SELECT * FROM suspicious_files ORDER BY timestamp DESC LIMIT 200')
        for threat in self.cursor.fetchall():
            threat_tree.insert('', 'end', values=threat[:7])
        
        threat_scrollbar = ttk.Scrollbar(threat_frame, orient='vertical', command=threat_tree.yview)
        threat_tree.configure(yscrollcommand=threat_scrollbar.set)
        
        threat_tree.pack(side='left', fill='both', expand=True)
        threat_scrollbar.pack(side='right', fill='y')
        
        # Add tabs
        notebook.add(usb_frame, text='📁 USB Events (200 recent)')
        notebook.add(alert_frame, text='🚨 Alerts (200 recent)')
        notebook.add(threat_frame, text='⚠️ Threats (200 recent)')
        notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Control buttons
        control_frame = tk.Frame(log_window)
        control_frame.pack(pady=10)
        
        def export_logs():
            filename = f"usb_security_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            try:
                import csv
                
                # Export all three tables
                tables = [
                    ('usb_events', 'USB Events'),
                    ('alerts', 'Alerts'),
                    ('suspicious_files', 'Suspicious Files')
                ]
                
                for table_name, description in tables:
                    self.cursor.execute(f'SELECT * FROM {table_name}')
                    rows = self.cursor.fetchall()
                    
                    if rows:
                        # Get column names
                        self.cursor.execute(f'PRAGMA table_info({table_name})')
                        columns = [col[1] for col in self.cursor.fetchall()]
                        
                        # Write to CSV
                        table_filename = f"{table_name}_{filename}"
                        with open(table_filename, 'w', newline='', encoding='utf-8') as f:
                            writer = csv.writer(f)
                            writer.writerow(columns)
                            writer.writerows(rows)
                        
                        self.log_message(f"Exported {len(rows)} {description} to {table_filename}", 
                                        False, "SUCCESS")
                
                messagebox.showinfo("Success", "Logs exported successfully!")
                
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
        
        def clear_logs():
            if messagebox.askyesno("Confirm", "Clear all logs? This cannot be undone!"):
                try:
                    self.cursor.execute('DELETE FROM usb_events')
                    self.cursor.execute('DELETE FROM alerts')
                    self.cursor.execute('DELETE FROM suspicious_files')
                    self.conn.commit()
                    
                    # Clear trees
                    for item in usb_tree.get_children():
                        usb_tree.delete(item)
                    for item in alert_tree.get_children():
                        alert_tree.delete(item)
                    for item in threat_tree.get_children():
                        threat_tree.delete(item)
                    
                    self.log_message("All logs cleared", False, "INFO")
                    messagebox.showinfo("Success", "Logs cleared successfully!")
                    
                except Exception as e:
                    messagebox.showerror("Error", f"Clear failed: {str(e)}")
        
        tk.Button(control_frame, text="📤 Export All Logs", font=('Segoe UI', 11),
                 bg='#2196f3', fg='white', width=15, command=export_logs).pack(side='left', padx=10)
        
        tk.Button(control_frame, text="🗑️ Clear All Logs", font=('Segoe UI', 11),
                 bg='#f44336', fg='white', width=15, command=clear_logs).pack(side='left', padx=10)
        
        tk.Button(control_frame, text="🔄 Refresh", font=('Segoe UI', 11),
                 bg='#4caf50', fg='white', width=15,
                 command=lambda: self.refresh_logs(usb_tree, alert_tree, threat_tree)).pack(side='left', padx=10)
        
        tk.Button(control_frame, text="📊 Statistics", font=('Segoe UI', 11),
                 bg='#ff9800', fg='white', width=15, command=self.show_statistics).pack(side='left', padx=10)
    
    def refresh_logs(self, usb_tree, alert_tree, threat_tree):
        """Refresh log trees"""
        # Clear trees
        for tree in [usb_tree, alert_tree, threat_tree]:
            for item in tree.get_children():
                tree.delete(item)
        
        # Reload USB events
        self.cursor.execute('SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT 200')
        for event in self.cursor.fetchall():
            usb_tree.insert('', 'end', values=event[:7])
        
        # Reload alerts
        self.cursor.execute('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 200')
        for alert in self.cursor.fetchall():
            alert_tree.insert('', 'end', values=alert[:5])
        
        # Reload threats
        self.cursor.execute('SELECT * FROM suspicious_files ORDER BY timestamp DESC LIMIT 200')
        for threat in self.cursor.fetchall():
            threat_tree.insert('', 'end', values=threat[:7])
        
        self.log_message("Logs refreshed", False, "INFO")
    
    def show_statistics(self):
        """Show statistics dialog"""
        try:
            # Get statistics
            self.cursor.execute('SELECT COUNT(*) FROM usb_events')
            total_events = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM alerts')
            total_alerts = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(*) FROM suspicious_files')
            total_threats = self.cursor.fetchone()[0]
            
            self.cursor.execute('SELECT COUNT(DISTINCT drive_letter) FROM usb_events')
            unique_drives = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT COUNT(*) FROM usb_events WHERE event_type = 'INSERTED'")
            insertions = self.cursor.fetchone()[0]
            
            self.cursor.execute("SELECT COUNT(*) FROM usb_events WHERE event_type = 'REMOVED'")
            removals = self.cursor.fetchone()[0]
            
            stats_text = f"""
            📊 SECURITY STATISTICS
            
            🔹 Total USB Events: {total_events}
            🔹 Unique USB Drives: {unique_drives}
            🔹 USB Insertions: {insertions}
            🔹 USB Removals: {removals}
            
            🚨 Total Alerts: {total_alerts}
            ⚠️ Threats Found: {total_threats}
            
            🔌 Currently Connected: {len(self.connected_usb)}
            📈 Monitoring Status: {'ACTIVE' if self.running else 'INACTIVE'}
            
            📅 Since: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            """
            
            messagebox.showinfo("Statistics", stats_text)
            
        except Exception as e:
            messagebox.showerror("Error", f"Could not load statistics: {str(e)}")
    
    def test_email(self):
        """Test email functionality"""
        if not self.config.get('email_username') or self.config.get('email_username') == 'your_email@gmail.com':
            messagebox.showwarning("Configuration Needed", 
                                 "Please configure email settings first!")
            self.open_settings()
            return
        
        self.log_message("Testing email alert system...", False, "INFO")
        test_msg = "This is a test alert from USB Security Monitor v3.0"
        
        if self.send_email_alert(test_msg, "TEST"):
            messagebox.showinfo("Success", "Test email sent successfully!")
        else:
            messagebox.showerror("Error", "Failed to send test email. Check your settings.")
    
    def refresh_display(self):
        """Refresh the display"""
        self.update_counts()
        self.update_footer()
        
        # Rescan connected USB
        if USB_DETECTION_ENABLED:
            current_usb = []
            for partition in psutil.disk_partitions():
                if 'removable' in partition.opts.lower():
                    current_usb.append(partition.device)
            self.update_usb_display(current_usb)
        
        self.log_message("Display refreshed", False, "INFO")
    
    def open_web_dashboard(self):
        """Open web dashboard in browser"""
        port = self.config.get('web_port', 8080)
        url = f"http://localhost:{port}"
        webbrowser.open(url)
        self.log_message(f"Opening web dashboard: {url}", False, "INFO")
    
    def start_web_dashboard(self):
        """Start web dashboard in background"""
        if not self.config.get('enable_web', True):
            return
        
        port = self.config.get('web_port', 8080)
        
        class DashboardHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    
                    # Get stats
                    cursor = self.server.app.cursor
                    
                    cursor.execute('SELECT COUNT(*) FROM usb_events')
                    event_count = cursor.fetchone()[0]
                    
                    cursor.execute('SELECT COUNT(*) FROM alerts')
                    alert_count = cursor.fetchone()[0]
                    
                    cursor.execute('SELECT COUNT(*) FROM suspicious_files')
                    threat_count = cursor.fetchone()[0]
                    
                    # Get recent events
                    cursor.execute('SELECT * FROM usb_events ORDER BY timestamp DESC LIMIT 10')
                    recent_events = ""
                    for event in cursor.fetchall():
                        recent_events += f"<li>{event[1]}: {event[2]} - {event[3]}</li>"
                    
                    # HTML template
                    html = f"""
                    <!DOCTYPE html>
                    <html>
                    <head>
                        <title>USB Security Dashboard</title>
                        <style>
                            body {{ 
                                font-family: 'Segoe UI', Arial, sans-serif; 
                                margin: 0; 
                                padding: 20px; 
                                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                                min-height: 100vh;
                                color: white;
                            }}
                            .container {{ 
                                max-width: 1200px; 
                                margin: 0 auto; 
                            }}
                            .header {{ 
                                text-align: center; 
                                margin-bottom: 40px; 
                            }}
                            .stats-grid {{ 
                                display: grid; 
                                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); 
                                gap: 20px; 
                                margin-bottom: 40px;
                            }}
                            .stat-card {{ 
                                background: rgba(255, 255, 255, 0.1); 
                                padding: 25px; 
                                border-radius: 15px; 
                                backdrop-filter: blur(10px);
                                border: 1px solid rgba(255, 255, 255, 0.2);
                            }}
                            .stat-number {{ 
                                font-size: 36px; 
                                font-weight: bold; 
                                margin: 10px 0;
                            }}
                            .events-panel {{ 
                                background: rgba(255, 255, 255, 0.1); 
                                padding: 25px; 
                                border-radius: 15px; 
                                backdrop-filter: blur(10px);
                                border: 1px solid rgba(255, 255, 255, 0.2);
                            }}
                            .event-list {{ 
                                list-style: none; 
                                padding: 0; 
                            }}
                            .event-list li {{ 
                                padding: 10px; 
                                margin: 5px 0; 
                                background: rgba(255, 255, 255, 0.1);
                                border-radius: 5px;
                            }}
                        </style>
                        <meta http-equiv="refresh" content="10">
                    </head>
                    <body>
                        <div class="container">
                            <div class="header">
                                <h1>🔐 USB Security Dashboard</h1>
                                <p>Real-time monitoring • Last update: {datetime.now().strftime('%H:%M:%S')}</p>
                            </div>
                            
                            <div class="stats-grid">
                                <div class="stat-card">
                                    <h3>📊 Total Events</h3>
                                    <div class="stat-number">{event_count}</div>
                                    <p>USB insertion/removal events</p>
                                </div>
                                
                                <div class="stat-card">
                                    <h3>🚨 Alerts</h3>
                                    <div class="stat-number" style="color: #ff6b6b;">{alert_count}</div>
                                    <p>Security alerts triggered</p>
                                </div>
                                
                                <div class="stat-card">
                                    <h3>⚠️ Threats</h3>
                                    <div class="stat-number" style="color: #ffa726;">{threat_count}</div>
                                    <p>Suspicious files detected</p>
                                </div>
                                
                                <div class="stat-card">
                                    <h3>🔌 Connected</h3>
                                    <div class="stat-number" style="color: #66bb6a;">{len(self.server.app.connected_usb)}</div>
                                    <p>Currently connected USB drives</p>
                                </div>
                            </div>
                            
                            <div class="events-panel">
                                <h3>📋 Recent Events</h3>
                                <ul class="event-list">
                                    {recent_events if recent_events else "<li>No recent events</li>"}
                                </ul>
                            </div>
                            
                            <div style="text-align: center; margin-top: 30px; color: rgba(255,255,255,0.7);">
                                <p>USB Security Monitor v3.0 • Auto-refreshes every 10 seconds</p>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                    
                    self.wfile.write(html.encode())
                else:
                    super().do_GET()
        
        def run_server():
            handler = DashboardHandler
            handler.app = self
            try:
                with socketserver.TCPServer(("", port), handler) as httpd:
                    print(f"🌐 Web dashboard available at http://localhost:{port}")
                    httpd.serve_forever()
            except OSError as e:
                if "Address already in use" in str(e):
                    print(f"⚠️  Port {port} already in use. Web dashboard not started.")
                else:
                    print(f"⚠️  Could not start web dashboard: {e}")
            except Exception as e:
                print(f"⚠️  Web dashboard error: {e}")
        
        # Start in background thread
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Don't auto-open browser to avoid popups
    
    def run(self):
        """Run the application"""
        self.root.mainloop()

# Main execution
if __name__ == "__main__":
    print("=" * 70)
    print("🚀 USB SECURITY MONITOR v3.0")
    print("=" * 70)
    
    print("\n📋 SYSTEM CHECK:")
    
    # Check requirements
    requirements = [
        ("psutil", USB_DETECTION_ENABLED, "pip install psutil"),
        ("sqlite3", True, "Built-in"),
        ("tkinter", True, "Built-in"),
        ("smtplib", True, "Built-in")
    ]
    
    all_ok = True
    for name, available, install_cmd in requirements:
        status = "✅" if available else "❌"
        print(f"  {status} {name}: {'Available' if available else 'Not available'}")
        if not available:
            print(f"     Install with: {install_cmd}")
            all_ok = False
    
    print("\n📊 FEATURES:")
    features = [
        "Real-time USB monitoring",
        "Popup security alerts",
        "Email notifications",
        "SQLite database logging",
        "Web dashboard (port 8080)",
        "USB scanning for threats",
        "Configurable settings",
        "Export logs to CSV"
    ]
    
    for feature in features:
        print(f"  ✓ {feature}")
    
    print("\n🔧 CONFIGURATION:")
    print("  • Edit 'usb_config.json' for email settings")
    print("  • Use Settings panel in application")
    print("  • Web dashboard: http://localhost:8080")
    
    print("\n🚀 STARTING APPLICATION...")
    print("   Monitoring will start automatically")
    print("   Insert a USB drive to test the system")
    
    try:
        app = USBSecuritySystem()
        app.run()
    except Exception as e:
        print(f"\n❌ CRITICAL ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")