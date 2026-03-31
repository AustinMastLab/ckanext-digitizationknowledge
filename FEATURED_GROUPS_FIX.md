# Featured Groups/Organizations Fix

## Problem Identified

Your featured groups/organizations functions were unreliable because:

1. **`group_list()` and `organization_list()` don't reliably return scheming fields** like `is_featured`, even with `include_extras=True`
2. Scheming fields are stored in the `group_extra` table and need direct database queries to retrieve reliably
3. The inconsistent behavior was due to CKAN's list actions sometimes including extras, sometimes not

## Solution Implemented

The solution uses the **core CKAN pattern** (from `ckan/lib/helpers.py`) combined with custom actions that properly query the database:

### 1. Custom Actions (`logic/action.py`)

Two new actions that query the database directly:

- **`featured_organization_list()`** - Returns list of featured org names
- **`featured_group_list()`** - Returns list of featured group names

These query the `group_extra` table directly for `is_featured=True` values.

### 2. Core CKAN Helper Pattern (`helpers.py`)

- **`featured_group_org()`** - Core CKAN implementation that:
  - Takes a list of featured items (from your custom actions)
  - Falls back to all groups/orgs if needed to reach the count
  - Calls `group_show`/`organization_show` for full details with datasets
  - Prevents duplicates
  - Limits results to requested count

- **`get_custom_featured_groups()`** - Uses the pattern above
- **`get_custom_featured_organizations()`** - Uses the pattern above

## How It Works

```python
# 1. Custom action gets names from database
featured_names = ['org1', 'org2']  # From featured_organization_list()

# 2. Core pattern gets full details
featured_group_org(
    items=featured_names,           # Start with featured items
    get_action='organization_show', # Get full details
    list_action='organization_list', # Fallback to all orgs if needed
    count=3                         # Want 3 results
)

# Result: Full org dicts with datasets, limited to 2 packages each
```

## Key Improvements

1. **✓ Reliable** - Direct database queries always find featured items
2. **✓ Consistent** - Matches core CKAN's implementation pattern
3. **✓ Flexible** - Handles multiple boolean representations ('True', 'true', '1', 'yes')
4. **✓ Efficient** - Only calls `show` actions for items that will be returned
5. **✓ Complete** - Returns full details matching core CKAN format

## Testing

### 1. Check Database

Run the debug script to see what's actually stored:

```bash
cd /home/ckanuser/ckan/ckan_dev/lib/src/ckanext-digitizationknowledge
# Edit debug_featured.py with your database URL first
python debug_featured.py
```

### 2. Test Actions

```python
# In CKAN shell or via API
import ckan.plugins.toolkit as toolkit

# Get featured org names
featured_orgs = toolkit.get_action('featured_organization_list')({}, {})
print(featured_orgs)  # Should show: ['org1', 'org2', ...]

# Get featured group names  
featured_groups = toolkit.get_action('featured_group_list')({}, {})
print(featured_groups)  # Should show: ['group1', 'group2', ...]
```

### 3. Test Helpers

```python
# In template or Python
from ckanext.digitizationknowledge import helpers

# Get 3 featured organizations with full details
orgs = helpers.get_custom_featured_organizations(count=3)
print(len(orgs))  # Should show: 3 (or fewer if less are featured)
print(orgs[0].keys())  # Should include: 'name', 'title', 'packages', etc.

# Get 5 featured groups
groups = helpers.get_custom_featured_groups(count=5)
```

## Troubleshooting

### If no featured items are returned:

1. **Check the database** - Run `debug_featured.py` to see actual values
2. **Verify is_featured is set** - Edit a group/org in CKAN UI and set Featured=Yes
3. **Check the value format** - The query looks for: `'True'`, `'true'`, `'1'`, or `'yes'`
4. **Restart CKAN** - After code changes: `sudo supervisorctl restart ckan-uwsgi:*`

### If value format is different:

If your boolean is stored differently (e.g., as `"1"` or `"on"`), update the filter in `action.py`:

```python
model.GroupExtra.value.in_(['True', 'true', '1', 'yes', 'YOUR_VALUE'])
```

## Comparison with Core CKAN

### Core CKAN Approach

```python
# Uses config file
ckan.featured_orgs = org1 org2 org3

# In template
{% for org in h.get_featured_organizations(3) %}
```

### Your Approach (Database-driven)

```python
# Uses schema field (no config needed)
# Edit org in UI -> Set "Featured" to "Yes"

# In template (same usage!)
{% for org in h.get_custom_featured_organizations(3) %}
```

## Benefits of Your Approach

- **✓ No config file edits** - Everything managed through UI
- **✓ Per-item control** - Each group/org has a featured checkbox
- **✓ Dynamic** - Changes take effect immediately
- **✓ User-friendly** - Non-technical users can feature items

## Files Changed

1. `ckanext/digitizationknowledge/logic/action.py` - Added custom actions
2. `ckanext/digitizationknowledge/helpers.py` - Updated helpers to use core pattern
3. `debug_featured.py` - New debugging script (optional)
