"""
Module to manage Web configuration (Protect -> Web) on Sophos Firewall. 
"""
from sophosfirewall_python.api_client import SophosFirewallAPIError

class WebFilterPolicy:
    """
    Manages Web Filter Policies
    """
    def __init__(self, api_client):
        self.api_client = api_client
        self.xml_tag = "WebFilterPolicy"

        # Get categories for rules
        resp = self.api_client.get_tag("WebFilterCategory")
        self.categories = [category['Name'] for category in resp['Response']['WebFilterCategory']]
        self.categories.append("All web traffic") # Add default category

        # Get URL Groups
        resp = self.api_client.get_tag("WebFilterURLGroup")
        self.url_groups = [group['Name'] for group in resp['Response']['WebFilterURLGroup']]

        # Get File Types
        resp = self.api_client.get_tag("FileType")
        self.file_types = [file_type['Name'] for file_type in resp['Response']['FileType']]

        # Get User Activities
        resp = self.api_client.get_tag("UserActivity")
        self.user_activities = [activity['Name'] for activity in resp['Response']['UserActivity']]

    def get(self, name=None):
        """
        Retrieves web filter policies.
        If name is provided, filters by name. Otherwise, retrieves all policies.
        """
        if name:
            return self.api_client.get_tag_with_filter(self.xml_tag, "Name", name, operator="=")
        return self.api_client.get_tag(self.xml_tag)

    def create(self, name, default_action, download_file_size_restriction, 
                 enable_reporting="Enable", download_file_size_restriction_enabled=None,
                 goog_app_domain_list=None, goog_app_domain_list_enabled=None,
                 youtube_filter_is_strict=None, youtube_filter_enabled=None,
                 enforce_safe_search=None, enforce_image_licensing=None,
                 xff_enabled=None, office_365_tenants_list=None,
                 office_365_directory_id=None, office_365_enabled=None,
                 quota_limit=60, description=None, rules=None, debug: bool = False):
        """
        Creates a new web filter policy.

        Args:
            name (str): Specify a name for the Web Filter Policy. Max 50 chars.
            default_action (str): Default action of the policy ('Allow' or 'Deny').
            download_file_size_restriction (int): Specify maximum allowed file download size in MB (0-1536).
            enable_reporting (str, optional): Select to enable reporting of policy. Defaults to "Enable". (API Default: Enable)
            download_file_size_restriction_enabled (str, optional): Enable ('1') or disable ('0') checking for maximum allowed file download size. Defaults to None.
            goog_app_domain_list (str, optional): Comma-separated list of domains allowed to access Google services. Max 256 chars. Defaults to None.
            goog_app_domain_list_enabled (str, optional): Enable ('1') or disable ('0') specifying domains for Google services. Defaults to None.
            youtube_filter_is_strict (str, optional): Adjust the policy used for YouTube Restricted Mode ('1' for strict, '0' for moderate). Defaults to None.
            youtube_filter_enabled (str, optional): Enable ('1') or disable ('0') YouTube Restricted Mode. Defaults to None.
            enforce_safe_search (str, optional): Enable ('1') or disable ('0') blocking of pornography and explicit content in search results. Defaults to None.
            enforce_image_licensing (str, optional): Enable ('1') or disable ('0') limiting search results to Creative Commons licensed images. Defaults to None.
            xff_enabled (str, optional): Enable ('1') or disable ('0') X-Forwarded-For header. Defaults to None.
            office_365_tenants_list (str, optional): Comma-separated list of domain names and domain IDs allowed to access Microsoft 365. Max 4096 chars. Defaults to None.
            office_365_directory_id (str, optional): Domain ID allowed to access the Microsoft 365 service. Max 50 chars. Defaults to None.
            office_365_enabled (str, optional): Turn on ('1') or off ('0') specifying domains/IDs for Microsoft 365. Defaults to None.
            quota_limit (int, optional): Maximum allowed time (1-1440 minutes) for browsing restricted web content under quota policy action. Defaults to 60. (API Default: 60)
            description (str, optional): Specify Policy description. Max 255 chars. Defaults to None.
            rules (list of dict, optional): Specify the rules contained in this policy. Defaults to None. See rule list structure below:
                - categories (list of dict): List of rule categories containing:
                    - id (str): Category Name
                    - type (str): Category type 
                - http_action (str, optional): HTTP action (Allow/Deny). Defaults to Deny.
                - https_action (str, optional): HTTPS action (Allow/Deny). Defaults to Deny.
                - follow_http_action (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - schedule (str, optional): Schedule name. Defaults to 'All The Time'
                - policy_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - ccl_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 0.
                - user_list (list of str, optional): List of users to apply this rule to. Defaults to None.
        """
        # Ensure rules is a list, even if None is passed
        if rules is None:
            rules = []

        for rule in rules:
            if "categories" in rule:
                for category in rule["categories"]:
                    if category.get("type") == "WebCategory":
                        if not category.get("id") in self.categories:
                            raise SophosFirewallAPIError(f"Category '{category.get('id')}' is not a valid Web Filter Category.")
                    if category.get("type") == "FileType":
                        if not category.get("id") in self.file_types:
                            raise SophosFirewallAPIError(f"File Type '{category.get('id')}' is not a valid File Type.")
                    if category.get("type") == "URLGroup":
                        if not category.get("id") in self.url_groups:
                            raise SophosFirewallAPIError(f"URL Group '{category.get('id')}' is not a valid URL Group.")
                    if category.get("type") == "UserActivity":
                        if not category.get("id") in self.user_activities:
                            raise SophosFirewallAPIError(f"User Activity '{category.get('id')}' is not a valid User Activity.")
                    if category.get("type") not in ["WebCategory", "FileType", "URLGroup", "UserActivity"]:
                        raise SophosFirewallAPIError(f"Category type '{category.get('type')}' is not valid. Must be 'WebCategory', 'FileType', 'URLGroup', or 'UserActivity'.")

        template_vars = {
            "name": name,
            "default_action": default_action,
            "enable_reporting": enable_reporting,
            "download_file_size_restriction": download_file_size_restriction,
            "download_file_size_restriction_enabled": download_file_size_restriction_enabled,
            "goog_app_domain_list": goog_app_domain_list,
            "goog_app_domain_list_enabled": goog_app_domain_list_enabled,
            "youtube_filter_is_strict": youtube_filter_is_strict,
            "youtube_filter_enabled": youtube_filter_enabled,
            "enforce_safe_search": enforce_safe_search,
            "enforce_image_licensing": enforce_image_licensing,
            "xff_enabled": xff_enabled,
            "office_365_tenants_list": office_365_tenants_list,
            "office_365_directory_id": office_365_directory_id,
            "office_365_enabled": office_365_enabled,
            "quota_limit": quota_limit,
            "description": description,
            "rules": rules
        }
        return self.api_client.submit_template(
            filename="createwebfilterpolicy.j2",
            template_vars=template_vars,
            debug=debug
        )

    def update(self, name, default_action=None, enable_reporting=None,
                 download_file_size_restriction=None, download_file_size_restriction_enabled=None,
                 goog_app_domain_list=None, goog_app_domain_list_enabled=None,
                 youtube_filter_is_strict=None, youtube_filter_enabled=None,
                 enforce_safe_search=None, enforce_image_licensing=None,
                 xff_enabled=None, office_365_tenants_list=None,
                 office_365_directory_id=None, office_365_enabled=None,
                 quota_limit=None, description=None, rules=None, rule_action="add", debug: bool = False):
        """
        Updates an existing web filter policy.
        Fetches the existing policy and applies changes only for provided arguments.
        Handles 'add' or 'replace' actions for rules.
        To remove specific rules, use rule_action='replace' with the desired final list of rules.
        The full policy object is sent in the update payload.

        Args:
            name (str): Specify a name for the Web Filter Policy. Max 50 chars. (Mandatory for identification)
            default_action (str, optional): Default action of the policy ('Allow' or 'Deny').
            enable_reporting (str, optional): Select to enable reporting of policy.
            download_file_size_restriction (int, optional): Specify maximum allowed file download size in MB (0-1536).
            download_file_size_restriction_enabled (str, optional): Enable ('1') or disable ('0') checking for maximum allowed file download size.
            goog_app_domain_list (str, optional): Comma-separated list of domains allowed to access Google services. Max 256 chars.
            goog_app_domain_list_enabled (str, optional): Enable ('1') or disable ('0') specifying domains for Google services.
            youtube_filter_is_strict (str, optional): Adjust the policy used for YouTube Restricted Mode ('1' for strict, '0' for moderate).
            youtube_filter_enabled (str, optional): Enable ('1') or disable ('0') YouTube Restricted Mode.
            enforce_safe_search (str, optional): Enable ('1') or disable ('0') blocking of pornography and explicit content in search results.
            enforce_image_licensing (str, optional): Enable ('1') or disable ('0') limiting search results to Creative Commons licensed images.
            xff_enabled (str, optional): Enable ('1') or disable ('0') X-Forwarded-For header.
            office_365_tenants_list (str, optional): Comma-separated list of domain names and domain IDs allowed to access Microsoft 365. Max 4096 chars.
            office_365_directory_id (str, optional): Domain ID allowed to access the Microsoft 365 service. Max 50 chars.
            office_365_enabled (str, optional): Turn on ('1') or off ('0') specifying domains/IDs for Microsoft 365.
            quota_limit (int, optional): Maximum allowed time (1-1440 minutes) for browsing restricted web content under quota policy action.
            description (str, optional): Specify Policy description. Max 255 chars.
            rules (list of dict, optional): Specify the rules contained in this policy. Defaults to None. See rule list structure below:
                - categories (list of dict): List of rule categories containing:
                    - id (str): Category Name
                    - type (str): Category type. Valid options are 'WebCategory', 'FileType', 'URLGroup', or 'UserActivity'.
                - http_action (str, optional): HTTP action (Allow/Deny). Defaults to Deny.
                - https_action (str, optional): HTTPS action (Allow/Deny). Defaults to Deny.
                - follow_http_action (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - schedule (str, optional): Schedule name. Defaults to 'All The Time'
                - policy_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 1.
                - ccl_rule_enabled (str, optional): '1' to enable, '0' to disable. Defaults to 0.
                - user_list (str, optional): List of users to apply this policy to. Defaults to "None".
            rule_action (str, optional): Action for rules ('add' or 'replace'). Defaults to "add".
        """
        updated_policy_data = self.get(name=name)['Response'][self.xml_tag]

        # Update scalar fields if new values are provided
        if default_action is not None: updated_policy_data["DefaultAction"] = default_action
        if enable_reporting is not None: updated_policy_data["EnableReporting"] = enable_reporting
        if download_file_size_restriction is not None: updated_policy_data["DownloadFileSizeRestriction"] = download_file_size_restriction
        if download_file_size_restriction_enabled is not None: updated_policy_data["DownloadFileSizeRestrictionEnabled"] = download_file_size_restriction_enabled
        if goog_app_domain_list is not None: updated_policy_data["GoogAppDomainList"] = goog_app_domain_list
        if goog_app_domain_list_enabled is not None: updated_policy_data["GoogAppDomainListEnabled"] = goog_app_domain_list_enabled
        if youtube_filter_is_strict is not None: updated_policy_data["YoutubeFilterIsStrict"] = youtube_filter_is_strict
        if youtube_filter_enabled is not None: updated_policy_data["YoutubeFilterEnabled"] = youtube_filter_enabled
        if enforce_safe_search is not None: updated_policy_data["EnforceSafeSearch"] = enforce_safe_search
        if enforce_image_licensing is not None: updated_policy_data["EnforceImageLicensing"] = enforce_image_licensing
        if xff_enabled is not None: updated_policy_data["XFFEnabled"] = xff_enabled
        if office_365_tenants_list is not None: updated_policy_data["Office365TenantsList"] = office_365_tenants_list
        if office_365_directory_id is not None: updated_policy_data["Office365DirectoryId"] = office_365_directory_id
        if office_365_enabled is not None: updated_policy_data["Office365Enabled"] = office_365_enabled
        if quota_limit is not None: updated_policy_data["QuotaLimit"] = quota_limit
        if description is not None: updated_policy_data["Description"] = description

        # Rules handling
        rule_list = []
        if "RuleList" in updated_policy_data and not rule_action == "replace": # If we are not replacing, keep existing rules
            if isinstance(updated_policy_data["RuleList"]["Rule"], dict):
                rule_list = [updated_policy_data["RuleList"]["Rule"]]
            if isinstance(updated_policy_data["RuleList"]["Rule"], list):
                rule_list = updated_policy_data["RuleList"]["Rule"]

        if rules and (rule_action == "add" or rule_action == "replace"):
            for rule in rules:
                category_list = []
                for category in rule.get("categories", []):
                    if category.get("type") == "WebCategory":
                        if not category.get("id") in self.categories:
                            raise SophosFirewallAPIError(f"Category '{category.get('id')}' is not a valid Web Filter Category.")
                    if category.get("type") == "FileType":
                        if not category.get("id") in self.file_types:
                            raise SophosFirewallAPIError(f"File Type '{category.get('id')}' is not a valid File Type.")
                    if category.get("type") == "URLGroup":
                        if not category.get("id") in self.url_groups:
                            raise SophosFirewallAPIError(f"URL Group '{category.get('id')}' is not a valid URL Group.")
                    if category.get("type") == "UserActivity":
                        if not category.get("id") in self.user_activities:
                            raise SophosFirewallAPIError(f"User Activity '{category.get('id')}' is not a valid User Activity.")
                    if category.get("type") not in ["WebCategory", "FileType", "URLGroup", "UserActivity"]:
                        raise SophosFirewallAPIError(f"Category type '{category.get('type')}' is not valid. Must be 'WebCategory', 'FileType', 'URLGroup', or 'UserActivity'.")
                    category_list.append({
                        "ID": category.get("id", ""),
                        "type": category.get("type", "")
                    })
                rule_list.append({
                    "CategoryList": {"Category": category_list},
                    "HTTPAction": rule.get("http_action", "Deny"),
                    "HTTPSAction": rule.get("https_action", "Deny"),
                    "FollowHTTPAction": rule.get("follow_http_action", "1"),
                    "Schedule": rule.get("schedule", "All The Time"),
                    "PolicyRuleEnabled": rule.get("policy_rule_enabled", "1"),
                    "CCLRuleEnabled": rule.get("ccl_rule_enabled", "0"),
                    "UserList": {"User": rule.get("user_list", [])}
                })        

        if rule_list:
            if updated_policy_data.get("RuleList"):
                updated_policy_data["RuleList"]["Rule"] = rule_list

            if not updated_policy_data.get("RuleList"):
                updated_policy_data["RuleList"] = {"Rule": rule_list}

        return self.api_client.submit_template(
            filename="updatewebfilterpolicy.j2",
            template_vars=updated_policy_data, 
            debug=debug
        )

class UserActivity:
    """
    Manages User Activities.
    """
    def __init__(self, api_client):
        self.api_client = api_client
        self.xml_tag = "UserActivity"

        # Get categories
        resp = self.api_client.get_tag("WebFilterCategory")
        self.categories = [category['Name'] for category in resp['Response']['WebFilterCategory']]
        self.categories.append("All web traffic") # Add default category

        # Get URL Groups
        resp = self.api_client.get_tag("WebFilterURLGroup")
        self.url_groups = [group['Name'] for group in resp['Response']['WebFilterURLGroup']]

        # Get File Types
        resp = self.api_client.get_tag("FileType")
        self.file_types = [file_type['Name'] for file_type in resp['Response']['FileType']]

        
    def get(self, name=None):
        """
        Retrieves User Activities.
        If name is provided, filters by name. Otherwise, retrieves all policies.

        Args:
            name (str, optional): Name of the User Activity to filter by. Defaults to None
        """
        if name:
            return self.api_client.get_tag_with_filter(self.xml_tag, "Name", name, operator="=")
        return self.api_client.get_tag(self.xml_tag)

    def create(self, name, description: str=None, category_list: list[dict]=None, debug: bool = False):
        """
        Creates a new User Activity.

        Args:
            name (str): Specify a name for the User Activity. Max 50 chars.
            description (str, optional): Specify a description for the User Activity. Defaults to None.
            category_list (list of dict, optional): List of categories to apply to this User Activity. Defaults to None. Category dict format below:
                
                Each category dict should contain:
                    - id (str): Category Name
                    - type (str): Category type. Supports 'web category', 'file type', or 'url group'.
        """

        if category_list:
            for category in category_list:
                if category.get("type") == "web category":
                    if not category.get("id") in self.categories:
                        raise SophosFirewallAPIError(f"Category '{category.get('id')}' is not a valid Web Filter Category.")
                if category.get("type") == "file type":
                    if not category.get("id") in self.file_types:
                        raise SophosFirewallAPIError(f"File Type '{category.get('id')}' is not a valid File Type.")
                if category.get("type") == "url group":
                    if not category.get("id") in self.url_groups:
                        raise SophosFirewallAPIError(f"URL Group '{category.get('id')}' is not a valid URL Group.")
                if category.get("type") not in ["web category", "file type", "url group"]:
                    raise SophosFirewallAPIError(f"Category type '{category.get('type')}' is not valid. Must be 'web category', 'file type', or 'url group'.")
       
        template_vars = {
            "name": name,
            "description": description,
            "category_list": category_list if category_list else []
        }

        return self.api_client.submit_template(
            filename="createuseractivity.j2",
            template_vars=template_vars,
            debug=debug
        )