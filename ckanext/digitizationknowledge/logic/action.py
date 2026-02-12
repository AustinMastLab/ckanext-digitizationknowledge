import ckan.plugins.toolkit as tk
import ckan.authz as authz
import ckan.model as model
import ckanext.digitizationknowledge.logic.schema as schema


def _is_group_private_by_id(group_id):
    """
    Check if a group is private by querying its extras.
    
    Args:
        group_id: The group ID or name
        
    Returns:
        bool: True if group is marked as private
    """
    try:
        # Query group extras for is_private field
        group = model.Group.get(group_id)
        if not group:
            return False
            
        extra = model.Session.query(model.GroupExtra).filter(
            model.GroupExtra.group_id == group.id,
            model.GroupExtra.key == 'is_private'
        ).first()
        
        if extra:
            val = extra.value
            if isinstance(val, str):
                return val.lower() in ['true', '1', 'yes', 'on']
            return bool(val)
        return False
    except Exception:
        return False


def _user_is_member_of_group(user, group_id):
    """
    Check if a user is a member of a group.
    
    Args:
        user: Username string
        group_id: The group ID
        
    Returns:
        bool: True if user is a member
    """
    if not user:
        return False
    return authz.has_user_permission_for_group_or_org(group_id, user, 'read')


@tk.side_effect_free
def digitizationknowledge_get_sum(context, data_dict):
    tk.check_access(
        "digitizationknowledge_get_sum", context, data_dict)
    data, errors = tk.navl_validate(
        data_dict, schema.digitizationknowledge_get_sum(), context)

    if errors:
        raise tk.ValidationError(errors)

    return {
        "left": data["left"],
        "right": data["right"],
        "sum": data["left"] + data["right"]
    }


@tk.side_effect_free
@tk.chained_action
def group_list(original_action, context, data_dict):
    """
    Override default group_list to filter out private groups for non-members.
    
    - Sysadmins see all groups
    - Regular users see public groups + private groups they're members of
    - Anonymous users see only public groups
    """
    user = context.get('user')
    
    # Sysadmins see everything — no need to modify context
    if authz.is_sysadmin(user):
        return original_action(context, data_dict)
    
    # For all other users: bypass auth in the core action to prevent
    # group_show from throwing NotAuthorized on private groups when
    # all_fields=True.  We filter private groups out ourselves below.
    safe_context = context.copy()
    safe_context['ignore_auth'] = True
    all_groups = original_action(safe_context, data_dict)
    
    filtered_groups = []
    for group in all_groups:
        # Get group ID/name depending on response format
        if isinstance(group, dict):
            group_id = group.get('id') or group.get('name')
        else:
            group_id = group  # Just a string name
        
        # Check if this group is private
        if _is_group_private_by_id(group_id):
            # Private group - only include if user is a member
            if user and _user_is_member_of_group(user, group_id):
                filtered_groups.append(group)
        else:
            # Public group - include for everyone
            filtered_groups.append(group)
    
    return filtered_groups


def get_actions():
    return {
        'digitizationknowledge_get_sum': digitizationknowledge_get_sum,
        'group_list': group_list,
    }
