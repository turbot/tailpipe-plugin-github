import requests
from bs4 import BeautifulSoup
import json
from collections import defaultdict, Counter
from datetime import datetime

URL = "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/security-log-events"

def scrape_github_security_events(url):
    response = requests.get(url)
    response.raise_for_status()

    soup = BeautifulSoup(response.text, "html.parser")

    results = []
    events_section = soup.find("div", id="article-contents")

    if not events_section:
        print("Could not find expected article content section.")
        return results

    dts = events_section.find_all("dt", style="font-style:normal")
    for dt in dts:
        event_name_tag = dt.find("code")
        if not event_name_tag:
            continue

        event_name = event_name_tag.get_text(strip=True)

        # Now get the next sibling <dd> with "Fields"
        field_label = dt.find_next_sibling("dt", style="margin-left:1rem;font-style:normal")
        if not field_label or "Fields" not in field_label.get_text():
            continue

        # The <dd> that actually contains the fields is next
        fields_container = field_label.find_next_sibling("dd", style="margin-left:1rem")
        fields = []
        if fields_container:
            fields = [
                code.get_text(strip=True)
                for code in fields_container.find_all("code")
                if code.get_text(strip=True)
            ]

        if event_name and fields:
            results.append({
                "event_name": event_name,
                "fields": sorted(set(fields))
            })

    return results


def analyze_fields(events_data):
    """
    Analyze field usage across all events.
    
    Returns:
        dict: Field name -> list of events that use it
        Counter: Field name -> count of events
    """
    field_to_events = defaultdict(list)
    field_counter = Counter()
    
    for event in events_data:
        event_name = event['event_name']
        fields = event['fields']
        
        for field in fields:
            field_to_events[field].append(event_name)
            field_counter[field] += 1
    
    return field_to_events, field_counter


def generate_markdown_report(field_to_events, field_counter, total_events, output_file="field_analysis_report.md"):
    """Generate a comprehensive markdown report."""
    
    with open(output_file, 'w') as f:
        # Header
        f.write("# GitHub Security Log Event Field Analysis Report\n\n")
        f.write(f"*Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n\n")
       
        # Overview
        f.write("## Overview\n\n")
        f.write("This report analyzes the field usage patterns across all GitHub security log events. ")
        f.write("The analysis helps understand which fields are commonly used, which are unique to specific events, ")
        f.write("and provides insights into the overall structure of GitHub's security logging schema.\n\n")
        
        # Field Usage Statistics
        f.write("## Field Usage Statistics\n\n")
        f.write(f"- **Total unique fields**: {len(field_counter)}\n")
        f.write(f"- **Total events**: {total_events}\n")
        f.write(f"- **Average fields per event**: {sum(field_counter.values()) / total_events:.2f}\n\n")
        
        # Universal Fields
        universal_fields = [field for field, count in field_counter.items() if count == total_events]
        f.write("## Universal Fields\n\n")
        f.write("Fields that appear in **all** security log events:\n\n")
        if universal_fields:
            for field in sorted(universal_fields):
                f.write(f"- `{field}`\n")
        else:
            f.write("*No fields appear in all events.*\n")
        f.write("\n")
        
        # Unique Fields
        unique_fields = [field for field, count in field_counter.items() if count == 1]
        f.write("## Unique Fields\n\n")
        f.write("Fields that appear in **only one** event:\n\n")
        if unique_fields:
            f.write(f"**Total unique fields**: {len(unique_fields)}\n\n")
            for field in sorted(unique_fields):
                events = field_to_events[field]
                f.write(f"- `{field}` (used in: `{events[0]}`)\n")
        else:
            f.write("*No fields appear in only one event.*\n")
        f.write("\n")
        
        # Most Common Fields
        f.write("## Most Common Fields\n\n")
        f.write("Top 20 most frequently used fields:\n\n")
        f.write("| Rank | Field Name | Event Count | Percentage |\n")
        f.write("|------|------------|-------------|------------|\n")
        
        for i, (field, count) in enumerate(field_counter.most_common(20), 1):
            percentage = (count / total_events * 100) if total_events > 0 else 0
            f.write(f"| {i} | `{field}` | {count} | {percentage:.1f}% |\n")
        f.write("\n")
        
        # Complete Field Reference
        f.write("## Complete Field Reference\n\n")
        f.write("Complete list of all fields and the events that use them:\n\n")
        f.write("```\n")
        
        for field in sorted(field_to_events.keys()):
            count = field_counter[field]
            events = sorted(field_to_events[field])
            
            f.write(f"{field} ({count} events):\n")
            
            if count == total_events:
                # Universal field - appears in all events
                f.write(f"  - Used in all {total_events} events (universal field)\n")
            else:
                # List specific events for non-universal fields
                for event in events:
                    f.write(f"  - {event}\n")
            f.write("\n")
        
        f.write("```\n")
    
    return output_file


if __name__ == "__main__":
    print("🔍 Scraping GitHub security log events...")
    data = scrape_github_security_events(URL)
    
    # Step 1: Save to JSON
    json_file = "fields.json"
    with open(json_file, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"✅ Successfully scraped {len(data)} events and saved to {json_file}")
    
    # Step 2: Analyze fields
    print("📊 Analyzing field usage patterns...")
    field_to_events, field_counter = analyze_fields(data)
    
    # Step 3: Generate markdown report
    print("📝 Generating field analysis report...")
    report_file = generate_markdown_report(field_to_events, field_counter, len(data))
    print(f"✅ Field analysis report generated: {report_file}")
    
    print("\n🎉 Complete! Files generated:")
    print(f"   📄 {json_file} - Raw event data")
    print(f"   📋 {report_file} - Comprehensive field analysis")
    print(f"\n📈 Summary: {len(field_counter)} unique fields across {len(data)} events")
