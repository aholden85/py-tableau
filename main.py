#!/usr/bin/python3

import base64
import json
import re
import os
import requests

# The following packages are used to build a multi-part/mixed request.
from requests.packages.urllib3.fields import RequestField
from requests.packages.urllib3.filepost import encode_multipart_formdata


class TableauSession(requests.Session):
    def __init__(self, *args, **kwargs):
        super(TableauSession, self).__init__(*args, **kwargs)

    def init_basic_auth(self, auth_token):
        self.headers.update({"X-Tableau-Auth": auth_token})


class TableauClient(object):
    def __init__(self, server_url, version, site, username, password):
        # Initialize the session.
        self.__session = TableauSession()

        self.__endpoint = "{}/api/{}".format(
            server_url,
            version,
        )

        self.__sites = []

        # Sign-in to the Tableau site.
        resp = self.__session.request(
            method="POST",
            url="{}/auth/signin".format(
                self.__endpoint,
            ),
            data=json.dumps(
                {
                    "credentials": {
                        "name": username,
                        "password": password,
                        "site": {"contentUrl": site},
                    }
                }
            ),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )

        self.__session.init_basic_auth(resp.json()["credentials"]["token"])
        self.__site_id = resp.json()["credentials"]["site"]["id"]

    def __request(self, method, path, params=None, data=None, headers={}):
        # There are a specific set of methods that can be executed.
        valid_methods = [
            "GET",
            "OPTIONS",
            "HEAD",
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        ]
        if method not in valid_methods:
            raise ValueError(
                "TableauClient.__request: method must be one of {0}.".format(
                    valid_methods
                )
            )

        req = requests.Request(
            method=method,
            url="{}/sites/{}/{}".format(
                self.__endpoint,
                self.__site_id,
                path,
            ),
            params=params,
            data=data,
            headers=headers,
        )

        prep = self.__session.prepare_request(req)
        resp = self.__session.send(prep)
        return resp

    def __make_multipart(self, parts):
        """
        Creates one "chunk" for a multi-part upload
        'parts' is a dictionary that provides key-value pairs of the format name: (filename, body, content_type).
        Returns the post body and the content type string.
        For more information, see these URLs:
            https://medium.com/snake-charmer-python-and-analytics/publishing-to-tableau-server-via-python-post-requests-using-json-e76f2b5c6fe4
            http://stackoverflow.com/questions/26299889/how-to-post-multipart-list-of-json-xml-files-using-python-requests
        """
        mime_multipart_parts = []
        for name, (filename, blob, content_type) in parts.items():
            multipart_part = RequestField(name=name, data=blob, filename=filename)
            multipart_part.make_multipart(content_type=content_type)
            mime_multipart_parts.append(multipart_part)

        post_body, content_type = encode_multipart_formdata(mime_multipart_parts)
        content_type = "".join(("multipart/mixed",) + content_type.partition(";")[1:])
        return post_body, content_type

    def get_workbook_id(self, name):
        path = "workbooks?filter=name:eq:{}".format(
            name,
        )

        headers = {
            "Accept": "application/json",
        }

        resp = self.__request(
            method="GET",
            path=path,
            headers=headers,
        )

        if len(resp.json()["workbooks"]):
            return resp.json()["workbooks"]["workbook"][0]["id"]
        else:
            raise ValueError(
                "TableauClient.get_workbook_id: no workbooks found with name '{0}'.".format(
                    name,
                )
            )

    def download_workbook(self, workbook_id, extract_value=False):
        path = "workbooks/{}/content".format(
            workbook_id,
        )

        if extract_value:
            path = "{}?includeExtract={}".format(
                path,
                extract_value,
            )

        resp = self.__request(
            method="GET",
            path=path,
        )

        filename = re.findall(
            'filename="(.+)"$',
            resp.headers.get("content-disposition"),
        )[0]

        open(filename, "wb").write(resp.content)
        return filename

    def initiate_file_upload(self):
        path = "fileUploads"

        headers = {
            "Accept": "application/json",
        }

        return self.__request(method="POST", path=path, headers=headers,).json()[
            "fileUpload"
        ]["uploadSessionId"]

    def upload_workbook(self, workbook_file_path, promotion_config, overwrite=False):
        # The maximum size of a file that can be published in a single request is 64MB
        FILESIZE_LIMIT = 1024 * 1024 * 64  # 64MB

        # For when a workbook is over 64MB, break it into 5MB(standard chunk size) chunks
        CHUNK_SIZE = 1024 * 1024 * 5  # 5MB

        # Workbook file with extension, without full path
        workbook_file = os.path.basename(workbook_file_path)

        if not os.path.isfile(workbook_file_path):
            error = "{0}: file not found".format(workbook_file_path)
            raise IOError(error)

        # Break workbook file by name and extension
        workbook_file_name, workbook_file_extension = workbook_file.split(".", 1)

        if workbook_file_extension != "twbx":
            error = """
            As the REST API publish process cannot automatically include extracts or other 
            resources that the workbook uses. Therefore, a .twb file with data from a local 
            computer cannot be published. For simplicity, this function will only accept 
            .twbx files to publish.
            """
            raise TypeError(error)

        # Get workbook size to check if chunking is necessary
        workbook_size = os.path.getsize(workbook_file_path)
        chunked = workbook_size >= FILESIZE_LIMIT

        if chunked:
            # Workbook will publish in chunks as it is over 64MB.
            # Initiates an upload session
            upload_session_id = self.initiate_file_upload()

            # Read the contents of the file in chunks of 100KB
            with open(workbook_file_path, "rb") as f:
                while True:
                    data = f.read(CHUNK_SIZE)
                    if not data:
                        break
                    payload, content_type = self.__make_multipart(
                        {
                            "request_payload": ("", "", "text/xml"),
                            "tableau_file": ("file", data, "application/octet-stream"),
                        }
                    )

                    path = "fileUploads/{}".format(
                        upload_session_id,
                    )

                    headers = {
                        "Content-Type": content_type,
                        "Accept": "application/json",
                    }

                    self.__request(
                        method="PUT",
                        path=path,
                        data=payload,
                        headers=headers,
                    )

            # Finish building the request.
            path = "workbooks?uploadSessionId={}&workbookType={}&overwrite={}".format(
                upload_session_id,
                workbook_file_extension,
                str(overwrite).lower(),
            )

            request_payload = {
                "workbook": {
                    "name": workbook_file_name,
                    "connections": {
                        "connection": {
                            "serverAddress": promotion_config["db_server"],
                            "serverPort": promotion_config["db_port"],
                        },
                        "connectionCredentials": {
                            "name": promotion_config["db_user"],
                            "password": promotion_config["db_password"],
                        },
                    },
                    "project": {
                        "id": promotion_config["dst_pid"],
                    },
                }
            }

            payload, content_type = self.__make_multipart(
                {
                    "request_payload": (
                        None,
                        json.dumps(request_payload),
                        "application/json",
                    ),
                }
            )

            # Publish the workbook.
            return self.__request(
                method="POST",
                path=path,
                data=payload,
                headers={
                    "Content-Type": content_type,
                },
            ).json()["workbook"]["id"]
        else:
            # Workbook will publish in a single method as it is under 64MB.
            # Read the contents of the file to publish
            with open(workbook_file_path, "rb") as f:
                workbook_bytes = f.read()

            # Finish building the request.
            path = "workbooks?workbookType={}&overwrite={}".format(
                workbook_file_extension,
                str(overwrite).lower(),
            )

            request_payload = {
                "workbook": {
                    "name": workbook_file_name,
                    "connections": {
                        "connection": {
                            "serverAddress": promotion_config["db_server"],
                            "serverPort": promotion_config["db_port"],
                        },
                        "connectionCredentials": {
                            "name": promotion_config["db_user"],
                            "password": promotion_config["db_password"],
                        },
                    },
                    "project": {
                        "id": promotion_config["dst_pid"],
                    },
                }
            }

            payload, content_type = self.__make_multipart(
                {
                    "request_payload": (
                        None,
                        json.dumps(request_payload),
                        "application/json",
                    ),
                    "tableau_workbook": (
                        workbook_file,
                        workbook_bytes,
                        "application/octet-stream",
                    ),
                }
            )

            # Publish the workbook.
            return self.__request(
                method="POST",
                path=path,
                data=payload,
                headers={
                    "Content-Type": content_type,
                    "Accept": "application/json",
                },
            ).json()["workbook"]["id"]

    def update_extract_refresh(self, schedule_id, workbook_id):
        path = "schedules/{}/workbooks".format(
            schedule_id,
        )

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

        payload = {
            "task": {
                "extractRefresh": {
                    "workbook": {"id": workbook_id},
                },
            },
        }

        return self.__request(
            method="PUT",
            path=path,
            data=json.dumps(payload),
            headers=headers,
        )

    def query_workbooks(self):
        path = "workbooks"

        headers = {
            "Accept": "application/json",
        }

        return self.__request(
            method="GET",
            path=path,
            headers=headers,
        )

    def list_all_datasources(self):
        headers = {
            "Accept": "application/json",
        }

        for wb in self.query_workbooks().json()["workbooks"]["workbook"]:
            path = "workbooks/{}/connections".format(
                wb["id"],
            )

            resp = self.__request(
                method="GET",
                path=path,
                headers=headers,
            )

            for con in resp.json()["connections"]["connection"]:
                print(
                    "{}@{}:{}".format(
                        con["userName"],
                        con["serverAddress"],
                        con["serverPort"],
                    )
                )

    def query_projects(self):
        path = "projects"

        headers = {
            "Accept": "application/json",
        }

        return self.__request(
            method="GET",
            path=path,
            headers=headers,
        )

    def query_datasources(self):
        path = "datasources"

        headers = {
            "Accept": "application/json",
        }

        return self.__request(
            method="GET",
            path=path,
            headers=headers,
        )

    def list_all_extract_refreshes(self):
        path = "tasks/extractRefreshes"

        headers = {
            "Accept": "application/json",
        }

        return self.__request(
            method="GET",
            path=path,
            headers=headers,
        )

    def query_schedules(self):
        path = "schedules"

        headers = {
            "Accept": "application/json",
        }

        req = requests.Request(
            method="GET",
            url="{}/schedules".format(
                self.__endpoint,
            ),
            headers=headers,
        )

        prep = self.__session.prepare_request(req)
        resp = self.__session.send(prep)

        return resp