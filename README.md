# 🔐 USB Security Monitor v3.0 – Complete Project Documentation

---

## 📌 Abstract

USB Security Monitor v3.0 is a Python-based cyber security application designed to protect computer systems from malicious USB devices. The system continuously monitors USB insertion and removal events, scans connected USB drives for suspicious files, logs all activities into a database, generates real-time alerts via GUI popups and email notifications, and provides a live web-based dashboard for monitoring system status.

This project demonstrates practical implementation of **system security, automation, monitoring, and alerting mechanisms**, making it ideal for academic and real-world cyber security use cases.

---

## 🎯 Objectives

- Detect USB insertion and removal events in real time
- Prevent USB-based malware attacks
- Scan USB devices for suspicious executable files
- Maintain a detailed activity log
- Notify users through alerts and email
- Provide a user-friendly GUI and web dashboard

---

## 🛠 Technologies Used

| Category | Technology |
|-------|-----------|
| Programming Language | Python 3 |
| GUI Framework | Tkinter |
| USB Detection | psutil |
| Database | SQLite |
| Alerts | Popup + Email (SMTP) |
| Web Dashboard | Python HTTP Server |
| OS | Windows |

---

## 📂 Project Structure

```
USB-Security-Monitor/
│
├── usb_protector.py        # Main application file
├── usb_config.json        # Configuration settings
├── usb_security.db        # SQLite database
├── README.md              # Documentation (this file)
```

---

## ⚙️ System Requirements

### Hardware Requirements
- PC / Laptop
- USB Ports

### Software Requirements
- Windows OS
- Python 3.x

### Python Libraries
```bash
pip install psutil
```

> Note: tkinter, sqlite3, smtplib are built-in modules.

---

## ▶️ Step-by-Step Procedure to Run the Project

### Step 1: Open Project Folder
```bash
cd path\to\USB-Security-Monitor
```

### Step 2: Install Required Module
```bash
pip install psutil
```

### Step 3: Configure Email Alerts (Optional)
Edit `usb_config.json`:
```json
"email_username": "your_email@gmail.com",
"email_password": "your_app_password",
"admin_email": "receiver_email@gmail.com"
```

> Use Gmail **App Password**, not your regular password.

### Step 4: Run the Application
```bash
python usb_protector.py
```

### Step 5: Start Monitoring
- Click ▶ **Start** button
- Insert a USB device
- Observe alerts, logs, and scan results

### Step 6: Open Web Dashboard
```
http://localhost:8080
```

---

## 🔄 Overall System Flow Chart

```
+----------------------+
|   Start Application  |
+----------+-----------+
           |
           v
+----------------------+
| Load Configuration   |
+----------+-----------+
           |
           v
+----------------------+
| Initialize Database  |
+----------+-----------+
           |
           v
+----------------------+
| Start USB Monitoring |
+----------+-----------+
           |
           v
+----------------------+
| USB Inserted ?       |
+-----+-----------+----+
      | Yes        | No
      v            |
+------------------+  |
| Scan USB Device  |  |
+-----+------------+  |
      |               |
      v               v
+------------------+ +------------------+
| Threat Detected? | | Continue Monitor |
+-----+------------+ +------------------+
      | Yes
      v
+------------------+
| Alert + Log Data |
+------------------+
```

---

## 🔌 USB Detection Flow Diagram

```
USB Inserted
     |
     v
Detect Device (psutil)
     |
     v
Capture USB Details
     |
     v
Store in Database
     |
     v
Trigger Alert
```

---

## 🔍 USB Scanning Flow Diagram

```
Start Scan
   |
   v
Traverse USB Files
   |
   v
Check File Extension
   |
   v
Is Suspicious?
   |        |
  Yes      No
   |        |
   v        v
Log Threat  Continue
   |
   v
Alert User
```

---

## 🧠 Working Principle

1. The system starts and loads configuration settings
2. USB monitoring thread runs continuously
3. On USB insertion:
   - Device details are captured
   - Auto-scan starts
4. Suspicious file extensions are detected
5. Alerts are generated
6. Logs are stored in SQLite database
7. GUI and web dashboard update in real time

---

## 🗃 Database Design

### Tables Used

#### 1. usb_events
- Stores USB insertion/removal events

#### 2. alerts
- Stores alert messages and status

#### 3. suspicious_files
- Stores detected threat file details

---

## 🖥 User Interface Description

- **Main Dashboard** – Shows USB count, alerts, threats
- **Logs Panel** – Displays real-time logs
- **Alert Window** – Popup notification on threats
- **Web Dashboard** – Live statistics on browser

(Add screenshots here in report)

---

## 📈 Advantages

- Real-time USB monitoring
- Easy-to-use GUI
- Lightweight and fast
- Useful for security awareness

---

## ⚠️ Limitations

- Works only on Windows
- File-based detection only
- No automatic USB blocking

---

## 🔮 Future Enhancements

- VirusTotal API integration
- Machine learning-based detection
- Auto USB blocking
- Cross-platform support

---

## 🎓 Conclusion

USB Security Monitor v3.0 effectively demonstrates how USB-based threats can be detected and monitored using Python. The system provides a complete security monitoring solution with alerts, logging, and visualization, making it suitable for academic projects and basic real-world security applications.

---

## 👨‍💻 Author Details

**Project Name:** USB Security Monitor v3.0  
**Domain:** Cyber Security  
**Developed Using:** Python

---
[Main UI](screenshots/UI.png)
[USB Alert](screenshots/usb_inserted.png)
[log  Dashboard](screenshots/logs.png)
[Unplug](screenshots/unpluged.png)




## ✅ End of Document


