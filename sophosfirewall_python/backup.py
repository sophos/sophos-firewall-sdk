"""
Copyright 2023 Sophos Ltd.  All rights reserved.
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing
permissions and limitations under the License.
"""


class Backup:
    """Class for working with Backup settings."""

    def __init__(self, api_client):
        self.client = api_client

    def get(self, name=None):
        """Get backup details.

        Args:
            name (str, optional): Name of backup schedule. Returns all if not specified.

        Returns:
            dict: XML response converted to Python dictionary
        """
        if name:
            return self.client.get_tag_with_filter(
                xml_tag="BackupRestore", key="Name", value=name
            )
        return self.client.get_tag(xml_tag="BackupRestore")

    def update(self, backup_params, debug):
        """Updates scheduled backup settings

        Args:
            backup_params (dict): Dict containing backup settings
            debug (bool, optional): Enable debug mode. Defaults to False.

        Keyword Args:
            BackupMode (str): Backup mode (FTP/Mail/Local)
            BackupPrefix (str): Backup Prefix
            FTPServer (str, optional): FTP Server IP Address
            Username (str, optional): FTP Server username
            Password (str, optional): FTP Server password
            FtpPath (str, optional): FTP Server path
            EmailAddress (str): Email address
            BackupFrequency (str): Never/Daily/Weekly/Monthly
            Day (str): Day
            Hour (str): Hour
            Minute (str): Minute
            Date (str): Numeric representation of month
            EncryptionPassword (str, optional): Encryption password

        Returns:
            dict: XML response converted to Python dictionary
        """
        updated_params = {}
        current_params = self.get()["Response"]["BackupRestore"]["ScheduleBackup"]
        for param in current_params:
            if param in backup_params:
                updated_params[param] = backup_params[param]
            else:
                updated_params[param] = current_params[param]

        resp = self.client.submit_template(
            "updatebackup.j2", template_vars=updated_params, debug=debug
        )
        return resp
