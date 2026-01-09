import ckan.plugins as plugins
import ckan.plugins.toolkit as toolkit
from collections import OrderedDict
import json
import os


# import ckanext.digitizationknowledge.cli as cli
import ckanext.digitizationknowledge.helpers as helpers
import ckanext.digitizationknowledge.views as views
from ckanext.digitizationknowledge.logic import (
    validators, auth
    # action, auth, validators
)


class DigitizationknowledgePlugin(plugins.SingletonPlugin):
    plugins.implements(plugins.IConfigurer)
    
    plugins.implements(plugins.IAuthFunctions)
    # plugins.implements(plugins.IActions)
    plugins.implements(plugins.IBlueprint)
    # plugins.implements(plugins.IClick)
    plugins.implements(plugins.ITemplateHelpers)
    plugins.implements(plugins.IValidators)
    plugins.implements(plugins.IFacets)
    plugins.implements(plugins.IPackageController)


    # List of fields that should be processed as JSON lists
     # Add fields as needed
    JSON_LIST_FIELDS = [
        'task_clusters',
        'task',
        'preparations',
        'audience',
        'discipline',
        'equipment',
        'in_language',
        'digitization_academy_course'
        # Add more fields here
    ]

    def _process_json_list_field(self, value, field_name='unknown'):
        """
        Process a field that should be a JSON list of strings
        
        Args:
            value: The value to process (string or list)
            field_name: Name of field for logging purposes
            
        Returns:
            list: Processed list of strings
        """
        print(f"Incoming {field_name}: {value} of type {type(value)}")
        
        try:
            # If it's a JSON string, parse it
            if isinstance(value, str) and value.strip().startswith('['):
                items = json.loads(value)
            # If it's already a list, use it as is
            elif isinstance(value, list):
                items = value
            else:
                items = []

            # Ensure all items are strings and remove empty values
            items = [str(item).strip() for item in items if item]
            
            print(f"Processed {field_name}: {items}")
            return items
            
        except json.JSONDecodeError:
            print(f"Error parsing JSON for {field_name}: {value}")
            return []
        except Exception as e:
            print(f"Unexpected error processing {field_name}: {str(e)}")
            return []






    # IConfigurer

    def update_config(self, config_):
        toolkit.add_template_directory(config_, "templates")
        print("Registering public directory:", os.path.join(os.path.dirname(__file__), 'public'))
        toolkit.add_public_directory(config_, "public")
        toolkit.add_resource("assets", "digitizationknowledge_theme")

    
    # IAuthFunctions

    def get_auth_functions(self):
        return auth.get_auth_functions()

    # IActions

    # def get_actions(self):
    #     return action.get_actions()

    # IBlueprint

    def get_blueprint(self):
        return views.get_blueprints()

    # IClick

    # def get_commands(self):
    #     return cli.get_commands()

    # ITemplateHelpers

    def get_helpers(self):
        return helpers.get_helpers()

    # IValidators

    def get_validators(self):
        return validators.get_validators()
    
    # IFacets
    # TODO make the facets dynamic thatcan be loaded from the ckan.ini config file without needing to change source code for the plugin.
    def dataset_facets(self, facets_dict, package_type):
        """Modify the facets_dict and return it
        """
        new_facets = OrderedDict()
        # Basic facets
        new_facets['task_clusters'] = toolkit._('Task Clusters')
        new_facets['task'] = toolkit._('Tasks')
        new_facets['preparations'] = toolkit._('Specimen Preparations')
        new_facets['tags'] = toolkit._('Tags')
        new_facets['digitization_academy_course'] = toolkit._('Digitization Academy Courses')
        new_facets['discipline'] = toolkit._('Discipline')
        new_facets['audience'] = toolkit._('Audience')
        new_facets['in_language']= toolkit._('Languages')
        
        # Advanced facets
        new_facets['category'] = toolkit._('Categories')
        new_facets['organization'] = toolkit._('Organizations')
 
        new_facets['groups'] = toolkit._('Groups')
        new_facets['in_digitization_academy_course'] = toolkit._('In Digitization Academy Courses')
        new_facets['type'] = toolkit._('Resource Types')
                

        # Return only the facets defined above, ignoring CKAN's default
        # facets entirely so the search interface shows exactly the
        # desired set in the specified order.


        return new_facets
    
    def group_facets(self, facets_dict, group_type, package_type):
        return facets_dict
    
    def organization_facets(self, facets_dict, organization_type, package_type):
        return facets_dict

    def before_dataset_index(self, pkg_dict):
        for field_name in self.JSON_LIST_FIELDS:
            if field_name in pkg_dict:
                pkg_dict[field_name] = self._process_json_list_field(
                    pkg_dict.get(field_name, ''),
                    field_name
                )
        return pkg_dict
   
    # Required methods with default implementations
    
    def before_dataset_search(self, search_params):
        return search_params

    def after_dataset_search(self, search_results, search_params):
        return search_results

    def before_dataset_view(self, pkg_dict):
        return pkg_dict

    def after_dataset_create(self, context, pkg_dict):
        return pkg_dict

    def after_dataset_update(self, context, pkg_dict):
        return pkg_dict

    def after_dataset_delete(self, context, pkg_dict):
        return pkg_dict

    def after_dataset_show(self, context, pkg_dict):
        return pkg_dict

    def create(self, entity):
        pass

    def edit(self, entity):
        pass

    def delete(self, entity):
        pass

    def read(self, entity):
        pass

