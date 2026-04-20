import ckan.plugins.toolkit as toolkit
import ckan.model as model
import ckan.authz as authz
from sqlalchemy import and_, not_, exists
from typing import Any
import os
import logging
import ckan.plugins.toolkit as tk
from functools import lru_cache
from markupsafe import Markup

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

def debug_request_info():
    request = getattr(tk, "request", None)

    if not request:
        return {
            "endpoint": "",
            "path": "",
            "blueprint": "",
            "view_args": {},
        }

    return {
        "endpoint": getattr(request, "endpoint", "") or "",
        "path": getattr(request, "path", "") or "",
        "blueprint": getattr(request, "blueprint", "") or "",
        "view_args": getattr(request, "view_args", {}) or {},
    }

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
        return Markup(content)
    except FileNotFoundError:
        log.debug('No extra head HTML file at %s', file_path)
        return Markup('')

def page_title_suffix():
    endpoint = (tk.request.endpoint or "").lower()

    exact_map = {
        # Organization
        "organization.index": tk._("Organizations"),
        "organization.read": tk._("Organizations"),
        "organization.read_base": tk._("Organizations"),
        "organization.about": tk._("About"),
        "organization.members": tk._("Members"),
        "organization.activity": tk._("Activity Stream"),
        "organization.activity_stream": tk._("Activity Stream"),
        "organization.organization_activity": tk._("Activity Stream"),

        # Group
        "group.index": tk._("Groups"),
        "group.read": tk._("Groups"),
        "group.read_base": tk._("Groups"),
        "group.about": tk._("About"),
        "group.members": tk._("Members"),
        "group.activity": tk._("Activity Stream"),
        "group.activity_stream": tk._("Activity Stream"),
        "group.group_activity": tk._("Activity Stream"),

        # Package / dataset
        "package.index": tk._("Datasets"),
        "package.read": tk._("Dataset"),
        "package.read_base": tk._("Dataset"),
        "package.search": tk._("Datasets"),
        "package.resources": tk._("Resources"),
        "package.comments": tk._("Comments"),
        "package.activity": tk._("Activity Stream"),
        "package.activity_stream": tk._("Activity Stream"),
        "package.new": tk._("Dataset"),
        "package.edit": tk._("Dataset"),
        "package.new_resource": tk._("Dataset"),
        "package.edit_view": tk._("Dataset"),

        # Resource
        "resource.read": tk._("Resource Version"),
        "resource.history": tk._("Resource Version"),
        "resource.edit": tk._("Resource"),
        "resource.comments": tk._("Comments"),
    }

    if endpoint in exact_map:
        return exact_map[endpoint]

    if endpoint.endswith(".comments"):
        return tk._("Comments")
    if endpoint.endswith(".activity") or endpoint.endswith(".activity_stream"):
        return tk._("Activity Stream")
    if endpoint.endswith(".members"):
        return tk._("Members")
    if endpoint.endswith(".about"):
        return tk._("About")
    if endpoint.endswith(".resources"):
        return tk._("Resources")
    if endpoint.endswith(".read") or endpoint.endswith(".read_base"):
        if endpoint.startswith("organization."):
            return tk._("Organizations")
        if endpoint.startswith("group."):
            return tk._("Groups")
        if endpoint.startswith("package."):
            return tk._("Dataset")

    return ""

def get_helpers():
    return {
        "get_custom_featured_groups": get_custom_featured_groups,
        "get_custom_featured_organizations": get_custom_featured_organizations,
        "is_group_private": is_group_private,
        "user_can_view_group": user_can_view_group,
        "get_extra_head_html": get_extra_head_html,
        "page_title_suffix": page_title_suffix,
        "debug_request_info": debug_request_info,
    }
