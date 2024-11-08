import json
from datetime import datetime, timedelta
import random
import pandas as pd
import numpy as np
from typing import List, Dict
import uuid
import time

class GitHubAuditLogGenerator:
    def __init__(self):
        self.base_time = datetime.now() - timedelta(days=90)
        
        # Load actions once
        with open('actions.txt', 'r') as f:
            self.all_actions = [line.strip() for line in f if line.strip()]
        
        # Pre-calculate common actions
        self.normal_actions = [a for a in self.all_actions if not any(x in a.lower() for x in ['fail', 'delete', 'remove'])]
        self.suspicious_actions = [a for a in self.all_actions if any(x in a.lower() for x in ['fail', 'delete', 'remove'])]
        
        # Predefine static data
        self.locations = {
            'normal': ['US', 'UK', 'CA', 'AU', 'DE', 'FR', 'JP', 'SG'],
            'suspicious': ['RU', 'CN', 'KP', 'IR', 'VE']
        }
        
        self.ip_ranges = {
            'US': ('50', '76'), 'UK': ('81', '82'), 'CA': ('99', '100'),
            'AU': ('101', '103'), 'DE': ('104', '107'), 'FR': ('108', '111'),
            'JP': ('112', '115'), 'SG': ('116', '119'), 'RU': ('176', '178'),
            'CN': ('180', '183'), 'KP': ('175', '175'), 'IR': ('184', '186'),
            'VE': ('186', '189')
        }

        # Predefine users with minimal data
        self.users = {
            'normal': {
                'johndoe': {'id': '2838961', 'repos': ['org/repo1', 'org/repo2']},
                'janesmith': {'id': '2838962', 'repos': ['org/repo3', 'org/repo4']},
                'bobwilson': {'id': '2838963', 'repos': ['org/repo5', 'repo6']}
            },
            'suspicious': {
                'alice_hacker': {'id': '2838964', 'repos': ['org/repo7', 'org/repo8']},
                'mallory_attacker': {'id': '2838965', 'repos': ['org/repo9', 'org/repo10']}
            },
            'bot': {
                'dependabot': {'id': '2838966', 'repos': ['org/repo1', 'org/repo2']},
                'renovate': {'id': '2838967', 'repos': ['org/repo4', 'org/repo5']}
            }
        }

        # Pre-generate some common values
        self.common_fields = {
            'org': 'turbot',
            'org_id': '38865304',
            'tp_index': 'github_audit_log',
            'tp_source_type': 'github_audit_log_api',
            'tp_partition': 'github_audit_logs',
            'public_repo': False,
            'operation_type': 'create',
            'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        }

    def generate_ip_batch(self, country_code: str, size: int) -> List[str]:
        """Generate multiple IPs at once for a country"""
        range_start, range_end = self.ip_ranges.get(country_code, ('192', '199'))
        return [f"{random.choice([range_start, range_end])}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}" 
                for _ in range(size)]

    def generate_batch(self, size: int, user: str, user_data: dict, action_type: str = 'normal') -> List[dict]:
        """Generate multiple records at once"""
        records = []
        base_records = size // 10  # Process in smaller chunks
        
        for _ in range(0, size, base_records):
            chunk_size = min(base_records, size - len(records))
            
            # Generate timestamps in batch
            timestamps = [self.base_time + timedelta(
                days=random.randint(0, 89),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            ) for _ in range(chunk_size)]
            
            # Generate IPs in batch
            location = random.choice(self.locations['suspicious' if action_type == 'suspicious' else 'normal'])
            ips = self.generate_ip_batch(location, chunk_size)
            
            # Generate actions in batch
            actions = random.choices(
                self.suspicious_actions if action_type == 'suspicious' else self.normal_actions,
                k=chunk_size
            )
            
            # Generate records in batch
            for i in range(chunk_size):
                timestamp = timestamps[i]
                epoch_ms = int(timestamp.timestamp() * 1000)
                
                record = {
                    **self.common_fields,
                    'actor': user,
                    'user': user,
                    'actor_id': user_data['id'],
                    'user_id': user_data['id'],
                    'actor_ip': ips[i],
                    'tp_source_ip': ips[i],
                    'tp_ips': [ips[i]],
                    'action': actions[i],
                    'created_at': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    'timestamp': timestamp.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3],
                    'tp_date': timestamp.strftime('%Y-%m-%d'),
                    'tp_timestamp': epoch_ms,
                    'tp_ingest_timestamp': epoch_ms + random.randint(1000, 9999),
                    'repo': random.choice(user_data['repos']),
                    'tp_id': f'cs{uuid.uuid4().hex[:20]}'
                }
                records.append(record)
        
        return records

    def generate_logs(self, total_records: int = 500000) -> None:
        """Generate the complete audit log dataset"""
        start_time = time.time()
        all_records = []
        
        # Calculate distributions
        suspicious_records = int(total_records * 0.15)
        normal_records = total_records - suspicious_records
        
        print("Generating normal records...")
        # Generate normal records
        for user_type in ['normal', 'bot']:
            records_per_user = normal_records // (len(self.users['normal']) + len(self.users['bot']))
            for user, user_data in self.users[user_type].items():
                all_records.extend(self.generate_batch(records_per_user, user, user_data))
        
        print("Generating suspicious records...")
        # Generate suspicious records
        records_per_user = suspicious_records // len(self.users['suspicious'])
        for user, user_data in self.users['suspicious'].items():
            all_records.extend(self.generate_batch(records_per_user, user, user_data, 'suspicious'))
        
        print("Converting to DataFrame...")
        # Convert to DataFrame and save
        df = pd.DataFrame(all_records)
        print("Saving to parquet...")
        df.to_parquet("github_audit_log.parquet", index=False)
        
        end_time = time.time()
        print(f"Generated {len(all_records)} records in {end_time - start_time:.2f} seconds")

if __name__ == "__main__":
    generator = GitHubAuditLogGenerator()
    generator.generate_logs(500000)