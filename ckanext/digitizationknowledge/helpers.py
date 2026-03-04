import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.authz as authz
from sqlalchemy import and_, not_, exists
from typing import Any
import os
import logging
from functools import lru_cache

log = logging.getLogger(__name__)


def is_group_private(group):
    """
    Template helper to check if a group is private.
    
    Args:
        group: A group dict or group object
        
    Returns:
        bool: True if group is marked as private
    """
    # Handle dict format (from group_show)
    if isinstance(group, dict):
        # Check direct field (may be present in some cases)
        if 'is_private' in group:
            val = group['is_private']
            if isinstance(val, str):
                return val.lower() in ['true', '1', 'yes', 'on']
            return bool(val)
        
        # Check extras list format
        extras = group.get('extras', [])
        for extra in extras:
            if extra.get('key') == 'is_private':
                val = extra.get('value')
                if isinstance(val, str):
                    return val.lower() in ['true', '1', 'yes', 'on']
                return bool(val)
    
    # Handle model object format
    elif hasattr(group, 'extras') and 'is_private' in group.extras:
        val = group.extras['is_private']
        if isinstance(val, str):
            return val.lower() in ['true', '1', 'yes', 'on']
        return bool(val)
    
    return False


def user_can_view_group(group_name_or_id):
    """
    Template helper to check if current user can view a group.
    
    Args:
        group_name_or_id: Group name or ID
        
    Returns:
        bool: True if user can view the group
    """
    try:
        user = toolkit.current_user.name if toolkit.current_user.is_authenticated else None
        context = {'user': user}
        toolkit.check_access('group_show', context, {'id': group_name_or_id})
        return True
    except toolkit.NotAuthorized:
        return False


def get_custom_featured_groups(count: int = 1):
    '''
    Returns a list of featured groups using the is_featured field.
    Excludes private groups from featured listings.
    Efficiently queries database first to find featured groups, then gets full details.
    '''
    try:
        # Subquery to find private groups
        private_groups_subquery = model.Session.query(model.GroupExtra.group_id).filter(
            model.GroupExtra.key == 'is_private',
            model.GroupExtra.value.in_(['True', 'true', '1', 'yes'])
        ).subquery()
        
        # Query database directly for featured group names (fast!)
        # Exclude private groups from featured results
        query = model.Session.query(model.Group.name).join(
            model.GroupExtra,
            model.Group.id == model.GroupExtra.group_id
        ).filter(
            model.Group.is_organization == False,
            model.Group.state == 'active',
            model.GroupExtra.key == 'is_featured',
            model.GroupExtra.value.in_(['True', 'true', '1', 'yes']),
            # Exclude private groups
            ~model.Group.id.in_(private_groups_subquery)
        ).distinct().limit(count)
        
        featured_names = [name for name, in query.all()]
        
        # Now get full details only for featured groups
        groups_data = []
        for group_name in featured_names:
            try:
                context = {
                    'ignore_auth': True,
                    'limits': {'packages': 2},
                    'for_view': True
                }
                data_dict = {
                    'id': group_name,
                    'include_datasets': True
                }
                group = toolkit.get_action('group_show')(context, data_dict)
                groups_data.append(group)
            except toolkit.ObjectNotFound:
                continue
        
        return groups_data
    except Exception:
        return []


def get_custom_featured_organizations(count: int = 1):
    '''
    Returns a list of featured organizations using the is_featured field.
    Efficiently queries database first to find featured orgs, then gets full details.
    '''
    try:
        # Query database directly for featured org names (fast!)
        query = model.Session.query(model.Group.name).join(
            model.GroupExtra,
            model.Group.id == model.GroupExtra.group_id
        ).filter(
            model.Group.is_organization == True,
            model.Group.state == 'active',
            model.GroupExtra.key == 'is_featured',
            model.GroupExtra.value.in_(['True', 'true', '1', 'yes'])
        ).distinct().limit(count)
        
        featured_names = [name for name, in query.all()]
        
        # Now get full details only for featured orgs
        orgs_data = []
        for org_name in featured_names:
            try:
                context = {
                    'ignore_auth': True,
                    'limits': {'packages': 2},
                    'for_view': True
                }
                data_dict = {
                    'id': org_name,
                    'include_datasets': True
                }
                org = toolkit.get_action('organization_show')(context, data_dict)
                orgs_data.append(org)
            except toolkit.ObjectNotFound:
                continue
        
        return orgs_data
    except Exception:
        return []


@lru_cache(maxsize=1)
def get_extra_head_html():
    """
    Read extra HTML to inject in <head> from assets/extra_head.html.
    Content is cached after first read to avoid repeated file I/O.
    Returns empty string if the file doesn't exist.
    """
    file_path = os.path.join(
        os.path.dirname(__file__), 'assets', 'extra_head.html'
    )
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        log.info('Loaded extra head HTML from %s', file_path)
        return content
    except FileNotFoundError:
        log.debug('No extra head HTML file at %s', file_path)
        return ''

def get_helpers():
    return {
        "get_custom_featured_groups": get_custom_featured_groups,
        "get_custom_featured_organizations": get_custom_featured_organizations,
        "is_group_private": is_group_private,
        "user_can_view_group": user_can_view_group,
        "get_extra_head_html": get_extra_head_html,
    }
