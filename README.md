# MANEE' Security System

MANEE' Security System is a command-line security tool that analyzes log files, detects suspicious activities, calculates risk levels, and allows security analysts to create incident tickets.

The system simulates a simplified **Security Operations Center (SOC)** workflow for monitoring and responding to security events.

---

## Target Users

- Cybersecurity Analysts
- SOC Teams
- Security Engineers
- Startups
- Cybersecurity Management Department

---

## User Stories

- As a security analyst, I want to analyze log files to detect suspicious activities.
- As a security analyst, I want the system to detect common attacks automatically.
- As a security analyst, I want to generate a report after analyzing logs.
- As a security analyst, I want to create tickets for detected incidents.

- As a system administrator, I want to view all created tickets so that I can monitor security incidents.
- As a system administrator**, I want to update ticket status so that incidents can be tracked until they are resolved.
- As a system administrator**, I want a dashboard overview so that I can quickly understand the security situation.


---

## Features

- User authentication (Admin / Employee)
- Log file analysis
- Security threat detection
- Risk score and threat level calculation
- Security report generation
- Ticket management system
- Admin dashboard

---

## Log File Requirements

The system only accepts **CSV log files** with the following structure:

timestamp, ip, event_type, username, request, command, file


Example:
timestamp,ip,event_type,username,request,command,file
2025-03-01 10:00:00,192.168.1.10,login_failed,admin,POST /login,,
2025-03-01 10:05:00,192.168.1.20,sql_query,user1,SELECT * FROM users WHERE '1'='1',,


---

## Detected Attacks

The system detects several types of threats:

- Brute Force Attack
- SQL Injection
- Suspicious PowerShell Activity
- Malicious File Download
- Suspicious RDP Activity

---

## Environment Variables

Configuration is stored in a `.env` file:

USERS_FILE=data/users.json
TICKETS_FILE=data/tickets.json
REPORT_FOLDER=reports
