import ckan.plugins.toolkit as tk
from ckan.types import AuthResult, Context, DataDict
import ckan.authz as authz
import ckan.logic.auth as logic_auth
from ckan.common import _ 



@tk.auth_allow_anonymous_access
def digitizationknowledge_get_sum(context, data_dict):
    return {"success": True}


def group_show(context: Context, data_dict: DataDict) -> AuthResult:
    '''
   Custom group_show that enforces membership for private groups.
    
    If group is private, only allow members and sysadmins.
    Otherwise, fall back to default behavior.
    '''

    user = context.get('user')
    group = logic_auth.get_group_object(context, data_dict)
    
    # We need the group object to check 'private'
    group = model.Group.get(group_id)
    if not group:
         # Delegate to core if not found, it will handle it (404)
         return {'success': True} 
         
    # Check if 'is_private' is set in extras
    is_private = group.extras.get('is_private', False)
    
    # Convert 'true'/'True' strings to bool if necessary (ckan sometimes stores extras as strings)
    if isinstance(is_private, str):
        is_private = is_private.lower() in ['true', '1', 'yes', 'on']

    if not is_private and group.state == 'active':
        # Public groups are visible to everyone
        return {'success': True}

    # Private groups require membership
    authorized = authz.has_user_permission_for_group_or_org(
        group.id, user, 'read')
    
    if authorized:
        return {'success': True}
    else: 
        return {
            'success': False, 
            'msg': _('User %s not authorized to read group %s') % (user, group.id)
        }
    

def get_auth_functions():
    return {
        "digitizationknowledge_get_sum": digitizationknowledge_get_sum,
        "group_show": group_show,
    }