# 🔧 QODER RESET TOOL

<div align="center">

[![Telegram Channel](https://img.shields.io/badge/Telegram-@codetaik-blue?style=for-the-badge&logo=telegram)](https://t.me/codetaik)
[![Community Group](https://img.shields.io/badge/Community-Code%20%26%20Talk-orange?style=for-the-badge&logo=telegram)](https://t.me/+k4fB8V7JmAwzMDE0)
[![Creator](https://img.shields.io/badge/Creator-MiWaCode-green?style=for-the-badge&logo=github)](https://github.com/MiWaCode)

</div>

A powerful Python CLI tool for managing Qoder application machine IDs and cleaning related data on Windows systems.

## 📋 Features

- **🔍 Process Status Check**: Monitor running Qoder processes and their machine IDs
- **🧹 Data Cleanup**: Remove all Qoder-related files and registry entries
- **🆔 Machine ID Management**: Generate new machine IDs or use existing ones
- **⚡ Auto-Monitoring**: Automatically apply machine IDs to new Qoder processes
- **🎨 Colorful Interface**: Modern CLI with ANSI color support

## 📥 Installation

### Method 1: Clone from GitHub
```bash
git clone https://github.com/MiWaCode/Qoder.git
cd Qoder
```

### Method 2: Download ZIP
1. Go to [MiWaCode/Qoder](https://github.com/MiWaCode/Qoder)
2. Click "Code" → "Download ZIP"
3. Extract the ZIP file

## ⚠️ Important Requirements

### 🔑 Administrator Privileges Required
**This tool MUST be run as Administrator** to function properly because it needs to:
- Access and modify other processes' memory
- Delete system files and registry entries
- Perform low-level Windows API operations

### 🐍 Python Requirements
- **Python 3.6+** (recommended: Python 3.8+)
- No external packages required - uses only built-in libraries

### 💻 System Requirements
- **Windows 7/8/10/11** (64-bit recommended)
- **Administrator privileges**
- **Qoder application** (target application)

## 🚀 Usage

### Step 1: Run as Administrator
1. Right-click on **Command Prompt** or **PowerShell**
2. Select **"Run as administrator"**
3. Navigate to the tool directory:
```cmd
cd "C:\path\to\your\Qoder\folder"
```

### Step 2: Execute the Tool
```cmd
python qoder.py
```

### Step 3: Select Options
The tool provides an interactive menu:

```
=============================================
           QODER RESET TOOL
Created by: https://t.me/codetaik
=============================================
1. Check Qoder status
2. Clear Qoder related files and registry
3. Machine ID management (use existing/generate new)
0. Exit
=============================================
```

## 📖 Menu Options Explained

### 1️⃣ Check Qoder Status
- Lists all running Qoder processes
- Shows Process ID, name, path, and base address
- Displays current machine ID for each process
- **Use this first** to see what's currently running

### 2️⃣ Clear Qoder Data
- **⚠️ CAUTION**: This option will permanently delete all Qoder data and settings.
- Confirmation prompt included for safety.
- Use when you want a complete clean slate.

### 3️⃣ Machine ID Management
Interactive submenu with options:
- **Use existing machine ID**: Apply saved ID to running processes
- **Generate new machine ID**: Create and apply a fresh UUID
- **Auto-monitoring option**: Automatically apply ID to future processes

## 🔄 Auto-Monitoring Feature

When enabled, the tool will:
- Run in the background
- Detect new Qoder processes automatically
- Apply the configured machine ID immediately
- Continue until you close the tool

**💡 Tip**: Enable auto-monitoring if you frequently restart Qoder

## 📁 Configuration File

The tool creates a `machine_id.txt` file in the same directory to store:
- Your current machine ID (UUID format)
- Example: `a1b2c3d4-e5f6-7890-abcd-ef1234567890`

## 🛠️ Troubleshooting

### Common Issues

#### "Access Denied" Errors
**Solution**: Make sure you're running as Administrator

#### "No Qoder processes found"
**Solution**: 
1. Start the Qoder application first
2. Then run this tool
3. Use option 1 to verify processes are detected

#### "Failed to modify machine ID"
**Possible causes**:
- Process protection/antivirus interference
- Qoder version incompatibility
- Insufficient privileges

**Solutions**:
- Temporarily disable antivirus
- Ensure Administrator privileges
- Try restarting both Qoder and this tool

#### Colors not showing in terminal
**Solutions**:
- Use **Windows Terminal** (recommended)
- Or use **PowerShell** instead of Command Prompt
- Colors work best in modern terminal applications

### Debug Mode
The tool includes detailed logging to help diagnose issues:
- Memory addresses and operations
- Process detection details
- Success/failure status for each operation

## 🔒 Security Notes

- This tool modifies process memory - some antivirus software may flag it
- Only use with legitimate Qoder installations
- The tool only targets processes named "qoder.exe"
- No network connections are made
- All operations are local to your system

## 📞 Support

- **Creator**: [@codetaik](https://t.me/codetaik)
- **Repository**: [MiWaCode/Qoder](https://github.com/MiWaCode/Qoder)

## 📄 License

This tool is provided as-is for educational and legitimate use purposes.

---

### 🎯 Quick Start Checklist

- [ ] Download from [MiWaCode/Qoder](https://github.com/MiWaCode/Qoder)
- [ ] Ensure Python 3.6+ is installed
- [ ] Run Command Prompt/PowerShell **as Administrator**
- [ ] Navigate to tool directory
- [ ] Run `python qoder.py`
- [ ] Start with option 1 to check current status
- [ ] Use option 3 for machine ID management

**Remember**: Always run as Administrator for full functionality! 🔑
