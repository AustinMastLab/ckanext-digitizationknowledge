#!/usr/bin/env python
"""
Debug script to check featured groups and organizations.
Run this from your CKAN directory with: python debug_featured.py
"""
import sys
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Update this with your CKAN database URL
DATABASE_URL = "postgresql://ckan_default:pass@localhost/ckan_default"

def check_featured_in_db():
    """Check what's actually stored in the database for is_featured field."""
    
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    print("=" * 80)
    print("CHECKING GROUPS WITH is_featured FIELD")
    print("=" * 80)
    
    query = """
        SELECT 
            g.name,
            g.title,
            g.is_organization,
            g.state,
            ge.key,
            ge.value
        FROM "group" g
        JOIN group_extra ge ON g.id = ge.group_id
        WHERE ge.key = 'is_featured'
        ORDER BY g.is_organization, g.name;
    """
    
    result = session.execute(query)
    rows = result.fetchall()
    
    if not rows:
        print("\n❌ NO groups or organizations found with 'is_featured' field!")
        print("\nTroubleshooting:")
        print("1. Make sure you've edited groups/orgs and set 'Featured' to 'Yes'")
        print("2. Check if the field is being saved correctly")
        print("3. The schema might not be applied correctly")
    else:
        print(f"\n✓ Found {len(rows)} items with is_featured field:\n")
        
        for row in rows:
            name, title, is_org, state, key, value = row
            org_type = "Organization" if is_org else "Group"
            status = "✓" if value in ['True', 'true', '1', 'yes'] else "✗"
            print(f"{status} {org_type}: {name} ({title})")
            print(f"   State: {state}, Field Value: '{value}' (type: {type(value).__name__})")
            print()
    
    print("=" * 80)
    print("CHECKING ALL GROUP EXTRAS (for debugging)")
    print("=" * 80)
    
    query_all = """
        SELECT 
            g.name,
            g.is_organization,
            ge.key,
            ge.value
        FROM "group" g
        JOIN group_extra ge ON g.id = ge.group_id
        WHERE g.state = 'active'
        ORDER BY g.name, ge.key
        LIMIT 20;
    """
    
    result_all = session.execute(query_all)
    rows_all = result_all.fetchall()
    
    print(f"\nShowing first 20 group extras:\n")
    current_group = None
    for row in rows_all:
        name, is_org, key, value = row
        if name != current_group:
            org_type = "Org" if is_org else "Group"
            print(f"\n{org_type}: {name}")
            current_group = name
        print(f"  - {key}: {value}")
    
    session.close()

if __name__ == "__main__":
    try:
        check_featured_in_db()
    except Exception as e:
        print(f"\n❌ Error: {e}")
        print("\nMake sure to update the DATABASE_URL in this script!")
        sys.exit(1)
