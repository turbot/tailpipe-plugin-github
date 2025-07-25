# GitHub Security Log Event Fields Scraper

## **📋 Overview**

This script scrapes [GitHub's official documentation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events) to extract security log event names and their associated fields. It automatically generates both structured JSON data and a comprehensive field analysis report in a single command.

## **🎯 Purpose**

The script automates the complete workflow of GitHub security log analysis by:

- **🔍 Scraping** event names and fields from GitHub's official documentation
- **💾 Generating** structured JSON data (`fields.json`) for programmatic use
- **📊 Analyzing** field usage patterns across all events
- **📝 Creating** a comprehensive markdown report (`field_analysis_report.md`)
- **🔄 Maintaining** up-to-date field mappings automatically

## **🔍 How It Works**

1. **Fetches** the GitHub security log events documentation page
2. **Parses HTML** using BeautifulSoup to locate event definitions
3. **Extracts** event names and associated field lists
4. **Analyzes** field distribution and usage patterns
5. **Generates** both JSON data and markdown analysis report

## **📦 Dependencies**

- `requests==2.31.0` - For fetching the documentation page
- `beautifulsoup4==4.12.2` - For HTML parsing
- Built-in Python modules: `json`, `collections`, `datetime`

## **🚀 Quick Start**

### **1️⃣ Navigate to Script Directory**

From the repository root, navigate to the script directory:

```sh
cd scripts/security_event_fields_scrapper
```

**Important:** All commands must be run from this directory (`scripts/security_event_fields_scrapper/`).

### **2️⃣ Install Dependencies**

```sh
# Install Python 3 (if needed)
brew install python3  # For macOS users

# Install required packages
pip3 install -r requirements.txt
```

### **3️⃣ Run Complete Analysis**

```sh
python3 github_security_log_event_fields.py
```

This single command will:

- 🔍 Scrape the latest GitHub security events
- 💾 Save raw data to `fields.json`
- 📊 Analyze field usage patterns
- 📝 Generate `field_analysis_report.md`

## **📄 Generated Files**

### **`fields.json`** - Raw Data

```json
[
  {
    "event_name": "account.plan_change",
    "fields": ["@timestamp", "_document_id", "action", "actor", "user"]
  }
]
```

### **`field_analysis_report.md`** - Comprehensive Analysis

- **Field statistics**: Total fields, events, averages
- **Universal fields**: Fields appearing in all events
- **Unique fields**: Fields appearing in only one event
- **Usage rankings**: Most/least common fields
- **Complete reference**: All fields with their supporting events

## **🔧 Troubleshooting**

### **Externally Managed Environment Error**

If you see this error:

```
error: externally-managed-environment
× This environment is externally managed
```

**Solution:** Use a virtual environment:

```sh
# Navigate to the script directory
cd scripts/security_event_fields_scrapper

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # macOS/Linux
# OR
venv\Scripts\activate     # Windows

# Install dependencies and run
pip install -r requirements.txt
python3 github_security_log_event_fields.py

# When finished
deactivate
```

### **Network/Parsing Issues**

- **Network errors**: Check internet connection and GitHub accessibility
- **Empty results**: GitHub documentation structure may have changed
- **Parsing errors**: Verify HTML selectors in the script

## **📈 Sample Output**

```
🔍 Scraping GitHub security log events...
✅ Successfully scraped 334 events and saved to fields.json
📊 Analyzing field usage patterns...
📝 Generating field analysis report...
✅ Field analysis report generated: field_analysis_report.md

🎉 Complete! Files generated:
   📄 fields.json - Raw event data
   📋 field_analysis_report.md - Comprehensive field analysis

📈 Summary: 164 unique fields across 334 events
```

## **🔄 Automation**

This script can be integrated into CI/CD pipelines or scheduled tasks to automatically update security log event field mappings when GitHub's documentation changes.

## **📚 Use Cases**

- **Security monitoring**: Understanding available log fields
- **Parser development**: Building GitHub audit log parsers
- **Compliance tools**: Creating security event analyzers
- **Documentation**: Maintaining field reference guides
