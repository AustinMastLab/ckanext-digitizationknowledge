import ckan.plugins.toolkit as tk
from ckan import model
import ckan.authz as authz
import ckan.logic as logic


@tk.auth_allow_anonymous_access
def digitizationknowledge_get_sum(context, data_dict):
    return {"success": True}


def group_show(context, data_dict):
    '''
    Override group_show auth.
    
    If group is private, only allow members and sysadmins.
    Otherwise, fall back to default behavior.
    '''
    # Get the group 
    group_id = data_dict.get('id')
    user = context.get('user')
    
    
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
        
    if is_private:
         # Check if user is sysadmin
         if authz.is_sysadmin(user):
             return {'success': True}
             
         # Check if user is a member of the group
         # We use logic.check_access logic essentially but here we are IN the check_access
         
         # Is there a user?
         if not user:
             return {'success': False, 'msg': 'Private group. Login required.'}
             
         user_id = authz.get_user_id_for_username(user, allow_none=True)
         if not user_id:
             return {'success': False, 'msg': 'User not found'}
             
         # Check membership
         # We can check specific capacity if needed, but 'member' of any kind is likely enough
         query = model.Session.query(model.Member) \
            .filter(model.Member.group_id == group.id) \
            .filter(model.Member.table_id == user_id) \
            .filter(model.Member.state == 'active') \
            .filter(model.Member.table_name == 'user')
            
         if query.count() > 0:
             return {'success': True}
             
         return {'success': False, 'msg': 'Not authorized to view this private group'}
    
    # Check default permission if not private
    # We cannot call existing 'group_show' easily without causing recursion if we registered this
    # as the replacement.
    # However, standard CKAN auth functions often check 'group_show' logic.
    # The default 'group_show' logic in CKAN allows read if state is active.
    
    if group.state == 'active':
        return {'success': True}
        
    return {'success': False, 'msg': 'Group is not active'}


def get_auth_functions():
    return {
        "digitizationknowledge_get_sum": digitizationknowledge_get_sum,
    }