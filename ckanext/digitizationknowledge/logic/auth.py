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
    
    # Check if 'is_private' is set in extras
    is_private = False
    if 'is_private' in group.extras:
        val = group.extras['is_private']
        if isinstance(val, str):
            is_private = val.lower() in ['true', '1', 'yes', 'on']
        else:
            is_private = bool(val)

    # Public groups: allow if active and not private
    if group.state == 'active' and not is_private:
        return {'success': True}

    # Private groups or inactive: require membership
    authorized = authz.has_user_permission_for_group_or_org(
        group.id, user, 'read')
    if authorized:
        return {'success': True}
    else:
        return {'success': False, 'msg': _('User %s not authorized to read group %s') % (user, group.id)}
    

def get_auth_functions():
    return {
        "digitizationknowledge_get_sum": digitizationknowledge_get_sum,
        "group_show": group_show,
    }