# File: carbonblack_consts.py
#
# Copyright (c) 2016-2025 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
CARBONBLACK_JSON_DEVICE_URL = "device_url"
CARBONBLACK_JSON_API_TOKEN = "api_token"
CARBONBLACK_JSON_HASH = "hash"
CARBONBLACK_JSON_NAME = "name"
CARBONBLACK_JSON_QUERY = "query"
CARBONBLACK_JSON_READONLY = "read_only"
CARBONBLACK_JSON_ALERT_TYPE = "type"
CARBONBLACK_JSON_TOTAL_WATCHLISTS = "total_alerts"
CARBONBLACK_JSON_TOTAL_ENDPOINTS = "total_endpoints"
CARBONBLACK_JSON_NUM_RESULTS = "number_of_results"
CARBONBLACK_JSON_QUERY_TYPE = "type"
CARBONBLACK_JSON_ADDED_WL_ID = "new_watchlist_id"
CARBONBLACK_JSON_RANGE = "range"
CARBONBLACK_JSON_IPS = "ips"
CARBONBLACK_JSON_SENSOR_ID = "sensor_id"
CARBONBLACK_JSON_SESSION_ID = "session_id"
CARBONBLACK_JSON_FILE_DETAILS = "file_details"
CARBONBLACK_JSON_FILE_CB_URL = "cb_url"
CARBONBLACK_JSON_COMMENT = "comment"
CARBONBLACK_JSON_DOWNLOAD = "download"
CARBONBLACK_JSON_PID = "pid"
CARBONBLACK_JSON_PROCESS_NAME = "process_name"
CARBONBLACK_JSON_CB_ID = "carbonblack_process_id"
CARBONBLACK_JSON_VAULT_ID = "vault_id"
CARBONBLACK_JSON_DESTINATION_PATH = "destination"

CARBONBLACK_MSG_MORE_THAN_ONE = "More than one ONLINE system matched the endpoint ip/name."
CARBONBLACK_MSG_MORE_THAN_ONE += "<br>Please specify input params that matches a single ONLINE endpoint.<br>Systems Found:<br>{systems_error}"

CARBONBLACK_ERROR_CONNECTIVITY_TEST = "Test Connectivity Failed"
CARBONBLACK_SUCC_CONNECTIVITY_TEST = "Test Connectivity Passed"
CARBONBLACK_ERROR_PROCESS_SEARCH = "Process search failed"
CARBONBLACK_ERROR_INVALID_QUERY_TYPE = "Invalid query type, valid types are '{types}'"
CARBONBLACK_ERROR_INVALID_RANGE = "Invalid range, please specify in the format of start-end"
CARBONBLACK_ERROR_INVALID_ALERT_STATUS = "Invalid alert status, valid values are '{status}'"
CARBONBLACK_SUCC_SYNC_EVENTS = "Successfully synchronized sensor events."
CARBONBLACK_SUCC_QUARANTINE = "Quarantine action succeeded. It might take some time for the endpoint to get isolated."
CARBONBLACK_SUCC_UNQUARANTINE = "Unquarantine action succeeded. It might take some time for the endpoint to take effect."
CARBONBLACK_SUCC_BLOCK = "Block hash action succeeded. It might take some time for blacklisting to take effect."
CARBONBLACK_SUCC_UNBLOCK = "Unblock hash action succeeded. It might take some time for unblocking to take effect."
CARBONBLACK_MSG_FILE_NOT_FOUND = "File Not Found"
CARBONBLACK_ERROR_NO_ENDPOINTS = "Unable to find any endpoints with hostname/IP {0}"
CARBONBLACK_SUCC_RESET_SESSION = "Sensor {session_id} successfully reset"
CARBONBLACK_ERROR_RESET_SESSION = "Session {session_id} not found or is in an invalid state to keep alive"

CARBONBLACK_ADDED_WATCHLIST = "Added alert"
CARBONBLACK_ADDING_WATCHLIST = "Adding alert"
CARBONBLACK_DOING_SEARCH = "Doing {query_type} search"
CARBONBLACK_FETCHING_WATCHLIST_INFO = "Fetching watchlist info"
CARBONBLACK_USING_BASE_URL = "Using base url: {base_url}"
CARBONBLACK_RUNNING_QUERY = "Running query"
CARBONBLACK_DISPLAYING_RESULTS_TOTAL = "Displaying {displaying} '{query_type}' results of total {total}"

CARBONBLACK_QUERY_TYPE_ALERT = "alert"
CARBONBLACK_QUERY_TYPE_BINARY = "binary"
CARBONBLACK_QUERY_TYPE_PROCESS = "process"

VALID_QUERY_TYPE = [CARBONBLACK_QUERY_TYPE_ALERT, CARBONBLACK_QUERY_TYPE_BINARY, CARBONBLACK_QUERY_TYPE_PROCESS]

CARBONBLACK_ALERT_STATUS_RESOLVED = "Resolved"
CARBONBLACK_ALERT_STATUS_FALSE_POSITIVE = "False Positive"
CARBONBLACK_ALERT_STATUS_IN_PROGRESS = "In Progress"
CARBONBLACK_ALERT_STATUS_UNRESOLVED = "Unresolved"

VALID_ALERT_STATUS = [
    CARBONBLACK_ALERT_STATUS_RESOLVED,
    CARBONBLACK_ALERT_STATUS_FALSE_POSITIVE,
    CARBONBLACK_ALERT_STATUS_IN_PROGRESS,
    CARBONBLACK_ALERT_STATUS_UNRESOLVED,
]

CARBONBLACK_SLEEP_SECS = 5
CARBONBLACK_COMMAND_FAILED = "Command {command} failed with code: {code}, desc: {desc}"
CARBONBLACK_ERROR_POLL_TIMEOUT = "Could not get a connection to a live active session on the endpoint after {max_tries} polls."
CARBONBLACK_ERROR_MULTI_ENDPOINTS = (
    "{num_endpoints} endpoints matched (see results for a list). Please specify an IP/Host Name that uniquely identifies an online endpoint."
)
CARBONBLACK_ERROR_FILE_EXISTS = "File id for sensor already exists. "
CARBONBLACK_ERROR_INVALID_PATH = "Windows cannot find specified path"
CARBONBLACK_ERROR_INVALID_DEST_FILE = "Please check if the destination filename already exists at the specified path"
CARBONBLACK_ERROR_INVALID_INTEGER_VALUE = 'Please provide a valid {msg} integer value in the "{param}"'
MAX_POLL_TRIES = 10

CARBONBLACK_FINISHED_PROCESSING = "Finished Processing {0:.0%}"

CARBONBLACK_ERROR_CODE_MSG = "Error code unavailable"
CARBONBLACK_ERROR_MSG = "Unknown error occurred. Please check the asset configuration and|or action parameters."
CARBONBLACK_UNICODE_DAMMIT_TYPE_ERROR_MSG = "Error occurred while connecting to the Carbon Black Response server."
CARBONBLACK_UNICODE_DAMMIT_TYPE_ERROR_MSG += " Please check the asset configuration and|or the action parameters."
CARBONBLACK_ERROR_UPDATE_ALERTS_PARAM_IDS = "Either 'query' or 'alert_ids' parameters are required for this action."
CARBONBLACK_GROUP_ID_MSG = "Group ID unavailable"
