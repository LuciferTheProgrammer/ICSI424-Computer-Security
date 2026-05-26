# ICSI424 - Computer Security

Project Source Code  
Rheinard Zadanowsky  
Emily Homrighaus

We built a **File Integrity Checker**.

Test numbers are available in:

```text
TestFiles/TestResults.txt
```

## Project Overview

This repository contains a Java-based File Integrity Checker created for a Computer Security course. The program monitors a selected directory and checks whether files have been modified, deleted, moved, renamed, or added.

The checker creates a baseline record of files in the chosen directory and then repeatedly compares the current state of the directory against that baseline. It uses multiple hashing algorithms to help detect file changes and alert the user when suspicious modifications are found.

## Features

- Java-based file integrity monitoring
- Monitors a user-selected directory
- Recursively checks files in subdirectories
- Creates a baseline record of file information
- Detects modified files
- Detects deleted, moved, or renamed files
- Detects newly added files
- Tracks file size changes
- Tracks last modified date changes
- Tracks permission changes
- Generates file hashes using:
  - MD5
  - SHA-256
  - SHA-512
- Compares current hash values against baseline hash values
- Displays popup alerts when changes are detected
- Logs events to a logger file
- Saves baseline data for future comparison
- Prints hashing performance statistics
- Runs the integrity check every minute

## Project Files

- `FileIntegrityChecker.java` - main program that creates baselines, monitors directories, detects file changes, generates hashes, logs events, and displays alerts
- `FileInfo.java` - stores file information such as file path, file size, last modified time, permissions, and hash values
- `HashInfo.java` - stores hashing algorithm statistics such as count, total time, comparisons, and matches

## How It Works

When the program starts, the user is prompted to enter the absolute path of the directory they want to monitor.

The program checks whether a saved baseline already exists. If no baseline exists, it creates one by scanning the selected directory and storing information about each file, including:

- File path
- File size
- Last modified time
- File permissions
- MD5 hash
- SHA-256 hash
- SHA-512 hash

After the baseline is created, the program continuously monitors the directory every minute. During each check, it scans the current files and compares them against the baseline.

If a file has changed, the program prints a message, logs the event, and displays a popup alert. The program can detect changes such as file content modification, permission changes, updated timestamps, deleted files, renamed files, moved files, and newly added files.

The program also generates performance statistics for each hashing algorithm, including how many times the algorithm was used, total runtime, average runtime, and matching accuracy.

## How to Run the Project

1. Clone the GitHub repository.

2. Run the main method of the `FileIntegrityChecker` class.

3. When prompted, enter the absolute path of the directory you would like to have checked.

4. The check will be run every minute and will print how long the check took and the accuracy of the check.

5. To stop the checker, simply end the process.

## Output Files

The program creates output folders/files for baseline and logging information.

### Baseline Output

```text
File_Integrity_Checker_Baseline/
```

This folder stores the baseline file information used for comparison.

### Logger Output

```text
File_Integrity_Checker_Logger/
```

This folder stores logged events from the checker.

## Technologies Used

- Java
- File I/O
- Recursive directory scanning
- Cryptographic hashing
- MD5
- SHA-256
- SHA-512
- HashMap
- ArrayList
- Swing popup alerts
- Baseline comparison
- Logging

## Purpose

This project was created for a Computer Security course to demonstrate how file integrity monitoring works.

The project shows how cryptographic hash functions can be used to detect file tampering by comparing current file states against a trusted baseline. It also demonstrates how changes to file size, timestamps, permissions, and hash values can indicate that a file may have been modified.
