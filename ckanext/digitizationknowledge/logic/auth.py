import ckan.plugins.toolkit as tk
from ckan.types import AuthResult, Context, DataDict
import ckan.authz as authz
import ckan.logic.auth as logic_auth
from ckan.common import _ 


def _is_group_private(group):
    """
    Check if group has is_private extra set to true.
    
    Args:
        group: A CKAN Group model object
        
    Returns:
        bool: True if group is marked as private
    """
    if hasattr(group, 'extras') and 'is_private' in group.extras:
        val = group.extras['is_private']
        if isinstance(val, str):
            return val.lower() in ['true', '1', 'yes', 'on']
        return bool(val)
    return False


def _user_has_group_permission(group_id, user, permission):
    """
    Check if user has a specific permission for a group.
    
    Args:
        group_id: The group ID
        user: Username string
        permission: Permission to check (e.g., 'read', 'update', 'delete', 'manage_group')
        
    Returns:
        bool: True if user has the permission
    """
    # Sysadmins always have permission
    if authz.is_sysadmin(user):
        return True
    
    # Check if user has the specific permission for this group
    return authz.has_user_permission_for_group_or_org(group_id, user, permission)


@tk.auth_allow_anonymous_access
def digitizationknowledge_get_sum(context, data_dict):
    return {"success": True}


@tk.auth_allow_anonymous_access
def group_show(context: Context, data_dict: DataDict) -> AuthResult:
    '''
    Custom group_show that enforces membership for private groups.
    
    If group is private, only allow members and sysadmins.
    Otherwise, fall back to default behavior.
    '''
    user = context.get('user')
    group = logic_auth.get_group_object(context, data_dict)
    
    # Check if group is private
    is_private = _is_group_private(group)

    # Public groups: allow if active
    if group.state == 'active' and not is_private:
        return {'success': True}

    # Private groups or inactive: require membership
    authorized = _user_has_group_permission(group.id, user, 'read')
    if authorized:
        return {'success': True}
    else:
        return {
            'success': False, 
            'msg': _('User %s not authorized to read group %s') % (user, group.id)
        }


def group_update(context: Context, data_dict: DataDict) -> AuthResult:
    '''
    Custom group_update that allows group admins (owners) to update private groups.
    
    Group admins and sysadmins can update any group.
    '''
    user = context.get('user')
    group = logic_auth.get_group_object(context, data_dict)
    
    authorized = _user_has_group_permission(group.id, user, 'update')
    if authorized:
        return {'success': True}
    else:
        return {
            'success': False,
            'msg': _('User %s not authorized to update group %s') % (user, group.id)
        }


def group_delete(context: Context, data_dict: DataDict) -> AuthResult:
    '''
    Custom group_delete that allows group admins (owners/creators) to delete private groups.
    
    Group admins and sysadmins can delete groups.
    '''
    user = context.get('user')
    group = logic_auth.get_group_object(context, data_dict)
    
    # Check if user has delete permission (group admins do)
    authorized = _user_has_group_permission(group.id, user, 'delete')
    if authorized:
        return {'success': True}
    else:
        return {
            'success': False,
            'msg': _('User %s not authorized to delete group %s') % (user, group.id)
        }


def group_member_create(context: Context, data_dict: DataDict) -> AuthResult:
    '''
    Custom group_member_create that allows group admins to add members to private groups.
    '''
    user = context.get('user')
    group = logic_auth.get_group_object(context, data_dict)
    
    # Check if user can manage group members
    authorized = _user_has_group_permission(group.id, user, 'manage_group')
    if authorized:
        return {'success': True}
    else:
        return {
            'success': False,
            'msg': _('User %s not authorized to add members to group %s') % (user, group.id)
        }


def group_member_delete(context: Context, data_dict: DataDict) -> AuthResult:
    '''
    Custom group_member_delete that allows group admins to remove members from private groups.
    '''
    user = context.get('user')
    group = logic_auth.get_group_object(context, data_dict)
    
    # Check if user can manage group members
    authorized = _user_has_group_permission(group.id, user, 'manage_group')
    if authorized:
        return {'success': True}
    else:
        return {
            'success': False,
            'msg': _('User %s not authorized to remove members from group %s') % (user, group.id)
        }


@tk.auth_allow_anonymous_access
def group_list(context: Context, data_dict: DataDict) -> AuthResult:
    '''
    Allow anyone to call group_list - filtering is done in the action.
    '''
    return {'success': True}


def get_auth_functions():
    return {
        "digitizationknowledge_get_sum": digitizationknowledge_get_sum,
        "group_show": group_show,
        "group_update": group_update,
        "group_delete": group_delete,
        "group_member_create": group_member_create,
        "group_member_delete": group_member_delete,
        "group_list": group_list,
    }