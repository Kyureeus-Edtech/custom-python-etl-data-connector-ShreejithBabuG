"""
MongoDB Query Examples for CERT Threat Intelligence Data
Demonstrates how to analyze and query the collected threat data
"""

import os
from pymongo import MongoClient
from dotenv import load_dotenv
from datetime import datetime, timedelta
from collections import Counter
import json


class ThreatIntelligenceAnalyzer:
    """Analyze threat intelligence data stored in MongoDB"""
    
    def __init__(self):
        """Initialize MongoDB connection"""
        load_dotenv()
        
        mongo_uri = os.getenv('MONGODB_URI', 'mongodb://localhost:27017/')
        db_name = os.getenv('MONGODB_DATABASE', 'threat_intelligence')
        
        self.client = MongoClient(mongo_uri)
        self.db = self.client[db_name]
    
    def get_total_threats(self):
        """Get total count of threats across all collections"""
        print("\n" + "="*60)
        print("TOTAL THREAT COUNTS")
        print("="*60)
        
        urlhaus_count = self.db.urlhaus_raw.count_documents({})
        feodo_count = self.db.feodo_tracker_raw.count_documents({})
        otx_count = self.db.otx_pulses_raw.count_documents({})
        
        print(f"URLhaus (Malware URLs):        {urlhaus_count:>6}")
        print(f"Feodo Tracker (C2 Servers):    {feodo_count:>6}")
        print(f"AlienVault OTX (Threat Pulses): {otx_count:>6}")
        print(f"{'Total:':30} {urlhaus_count + feodo_count + otx_count:>6}")
    
    def analyze_malware_families(self):
        """Analyze malware family distribution"""
        print("\n" + "="*60)
        print("TOP MALWARE FAMILIES")
        print("="*60)
        
        # From Feodo Tracker
        pipeline = [
            {"$group": {
                "_id": "$malware.family",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        results = list(self.db.feodo_tracker_raw.aggregate(pipeline))
        
        if results:
            print("\nFrom Feodo Tracker C2 Servers:")
            for item in results:
                family = item['_id'] or 'Unknown'
                count = item['count']
                print(f"  {family:20} {count:>5} servers")
        
        # From URLhaus tags
        print("\nFrom URLhaus Tags:")
        all_tags = []
        for doc in self.db.urlhaus_raw.find({}, {"tags": 1}):
            if doc.get('tags'):
                all_tags.extend(doc['tags'])
        
        if all_tags:
            tag_counts = Counter(all_tags).most_common(10)
            for tag, count in tag_counts:
                print(f"  {tag:20} {count:>5} URLs")
    
    def analyze_geographic_distribution(self):
        """Analyze geographic distribution of threats"""
        print("\n" + "="*60)
        print("GEOGRAPHIC DISTRIBUTION")
        print("="*60)
        
        # URLhaus hosts by country
        print("\nMalware Hosting (URLhaus):")
        pipeline = [
            {"$group": {
                "_id": "$host.country",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        results = list(self.db.urlhaus_raw.aggregate(pipeline))
        for item in results:
            country = item['_id'] or 'Unknown'
            count = item['count']
            print(f"  {country:3} {count:>5} URLs")
        
        # Feodo C2 servers by country
        print("\nC2 Servers (Feodo Tracker):")
        pipeline = [
            {"$group": {
                "_id": "$country",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        
        results = list(self.db.feodo_tracker_raw.aggregate(pipeline))
        for item in results:
            country = item['_id'] or 'Unknown'
            count = item['count']
            print(f"  {country:3} {count:>5} servers")
    
    def find_recent_threats(self, hours=24):
        """Find threats ingested in the last N hours"""
        print("\n" + "="*60)
        print(f"THREATS INGESTED IN LAST {hours} HOURS")
        print("="*60)
        
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        
        # URLhaus
        recent_urls = self.db.urlhaus_raw.count_documents({
            "ingestion_timestamp": {"$gte": cutoff}
        })
        print(f"\nRecent Malware URLs: {recent_urls}")
        
        if recent_urls > 0:
            sample = self.db.urlhaus_raw.find_one({
                "ingestion_timestamp": {"$gte": cutoff}
            })
            if sample:
                print(f"  Example: {sample.get('url', 'N/A')[:60]}...")
                print(f"  Threat: {sample.get('threat', 'N/A')}")
        
        # Feodo
        recent_c2 = self.db.feodo_tracker_raw.count_documents({
            "ingestion_timestamp": {"$gte": cutoff}
        })
        print(f"\nRecent C2 Servers: {recent_c2}")
        
        if recent_c2 > 0:
            sample = self.db.feodo_tracker_raw.find_one({
                "ingestion_timestamp": {"$gte": cutoff}
            })
            if sample:
                print(f"  Example: {sample.get('ip_address', 'N/A')}")
                print(f"  Malware: {sample.get('malware', {}).get('family', 'N/A')}")
        
        # OTX
        recent_pulses = self.db.otx_pulses_raw.count_documents({
            "ingestion_timestamp": {"$gte": cutoff}
        })
        print(f"\nRecent Threat Pulses: {recent_pulses}")
        
        if recent_pulses > 0:
            sample = self.db.otx_pulses_raw.find_one({
                "ingestion_timestamp": {"$gte": cutoff}
            })
            if sample:
                print(f"  Example: {sample.get('name', 'N/A')[:60]}...")
                print(f"  IOCs: {sample.get('indicator_count', 0)}")
    
    def search_by_keyword(self, keyword):
        """Search for threats related to a keyword"""
        print("\n" + "="*60)
        print(f"SEARCHING FOR: {keyword.upper()}")
        print("="*60)
        
        # Search URLhaus tags
        urlhaus_results = self.db.urlhaus_raw.count_documents({
            "tags": {"$regex": keyword, "$options": "i"}
        })
        print(f"\nURLhaus URLs: {urlhaus_results} matches")
        
        # Search Feodo malware families
        feodo_results = self.db.feodo_tracker_raw.count_documents({
            "malware.family": {"$regex": keyword, "$options": "i"}
        })
        print(f"Feodo C2 Servers: {feodo_results} matches")
        
        # Search OTX pulses
        otx_results = self.db.otx_pulses_raw.count_documents({
            "$or": [
                {"name": {"$regex": keyword, "$options": "i"}},
                {"description": {"$regex": keyword, "$options": "i"}},
                {"tags": {"$regex": keyword, "$options": "i"}}
            ]
        })
        print(f"OTX Threat Pulses: {otx_results} matches")
        
        # Show examples
        if urlhaus_results > 0:
            print("\nExample URLhaus match:")
            doc = self.db.urlhaus_raw.find_one({
                "tags": {"$regex": keyword, "$options": "i"}
            })
            if doc:
                print(f"  URL: {doc.get('url', 'N/A')[:60]}...")
                print(f"  Tags: {', '.join(doc.get('tags', []))}")
    
    def get_online_threats(self):
        """Get currently active/online threats"""
        print("\n" + "="*60)
        print("ACTIVE/ONLINE THREATS")
        print("="*60)
        
        # Online URLhaus URLs
        online_urls = self.db.urlhaus_raw.count_documents({
            "url_status": "online"
        })
        print(f"\nOnline Malware URLs: {online_urls}")
        
        # Online Feodo C2 servers
        online_c2 = self.db.feodo_tracker_raw.count_documents({
            "status": "online"
        })
        print(f"Online C2 Servers: {online_c2}")
        
        if online_c2 > 0:
            print("\nTop 5 Online C2 Servers:")
            for doc in self.db.feodo_tracker_raw.find(
                {"status": "online"},
                {"ip_address": 1, "malware.family": 1, "country": 1}
            ).limit(5):
                ip = doc.get('ip_address', 'N/A')
                malware = doc.get('malware', {}).get('family', 'Unknown')
                country = doc.get('country', 'N/A')
                print(f"  {ip:15} | {malware:15} | {country}")
    
    def export_to_json(self, collection_name, limit=10, filename=None):
        """Export sample data to JSON file"""
        if not filename:
            filename = f"{collection_name}_sample_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        
        print(f"\nExporting {limit} records from {collection_name} to {filename}...")
        
        # Get sample data
        docs = list(self.db[collection_name].find().limit(limit))
        
        # Convert ObjectId to string
        for doc in docs:
            if '_id' in doc:
                doc['_id'] = str(doc['_id'])
            if 'ingestion_timestamp' in doc:
                doc['ingestion_timestamp'] = doc['ingestion_timestamp'].isoformat()
        
        # Write to file
        with open(filename, 'w') as f:
            json.dump(docs, f, indent=2, default=str)
        
        print(f"✓ Exported to {filename}")
    
    def get_ioc_summary(self):
        """Get summary of Indicators of Compromise"""
        print("\n" + "="*60)
        print("INDICATORS OF COMPROMISE (IOC) SUMMARY")
        print("="*60)
        
        # Count IOCs from OTX pulses
        total_iocs = 0
        ioc_types = Counter()
        
        for pulse in self.db.otx_pulses_raw.find():
            indicators = pulse.get('indicators', [])
            total_iocs += len(indicators)
            for indicator in indicators:
                ioc_type = indicator.get('type', 'Unknown')
                ioc_types[ioc_type] += 1
        
        print(f"\nTotal IOCs from OTX: {total_iocs}")
        print("\nIOC Types:")
        for ioc_type, count in ioc_types.most_common():
            print(f"  {ioc_type:20} {count:>5}")
    
    def close(self):
        """Close MongoDB connection"""
        self.client.close()


def main():
    """Run all analysis examples"""
    print("\n" + "="*60)
    print("CERT THREAT INTELLIGENCE DATA ANALYSIS")
    print("="*60)
    print(f"Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    
    analyzer = ThreatIntelligenceAnalyzer()
    
    try:
        # Run analyses
        analyzer.get_total_threats()
        analyzer.analyze_malware_families()
        analyzer.analyze_geographic_distribution()
        analyzer.find_recent_threats(hours=24)
        analyzer.get_online_threats()
        analyzer.get_ioc_summary()
        
        # Example searches
        print("\n" + "="*60)
        print("EXAMPLE SEARCHES")
        print("="*60)
        
        # Search for specific malware
        analyzer.search_by_keyword("emotet")
        analyzer.search_by_keyword("cobalt")
        
        # Export samples
        print("\n" + "="*60)
        print("EXPORTING SAMPLES")
        print("="*60)
        analyzer.export_to_json("urlhaus_raw", limit=5)
        
        print("\n" + "="*60)
        print("ANALYSIS COMPLETE")
        print("="*60)
        print("\nFor more queries, check MongoDB documentation:")
        print("https://www.mongodb.com/docs/manual/tutorial/query-documents/")
        
    except Exception as e:
        print(f"\nError during analysis: {e}")
    
    finally:
        analyzer.close()


if __name__ == "__main__":
    main()