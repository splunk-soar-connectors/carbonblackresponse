# File: carbonblack_connector.py
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
#
#
import ctypes
import datetime
import json
import os
import re
import shutil
import socket
import struct
import sys
import time
import uuid
import zipfile

import magic
import phantom.app as phantom
import phantom.rules as ph_rules
import requests
import six.moves.urllib.parse
from bs4 import BeautifulSoup, UnicodeDammit
from parse import parse
from phantom.action_result import ActionResult
from phantom.base_connector import BaseConnector
from phantom.vault import Vault

from carbonblack_consts import *


class CarbonblackConnector(BaseConnector):
    # The actions supported by this connector
    ACTION_ID_TEST_CONNECTIVITY = "test_connectivity"
    ACTION_ID_HUNT_FILE = "hunt_file"
    ACTION_ID_CREATE_ALERT = "create_alert"
    ACTION_ID_LIST_ALERTS = "list_alerts"
    ACTION_ID_UPDATE_ALERTS = "update_alerts"
    ACTION_ID_LIST_ENDPOINTS = "list_endpoints"
    ACTION_ID_RUN_QUERY = "run_query"
    ACTION_ID_QUARANTINE_DEVICE = "quarantine_device"
    ACTION_ID_UNQUARANTINE_DEVICE = "unquarantine_device"
    ACTION_ID_SYNC_EVENTS = "sync_events"
    ACTION_ID_GET_SYSTEM_INFO = "get_system_info"
    ACTION_ID_LIST_PROCESSES = "list_processes"
    ACTION_ID_GET_FILE = "get_file"
    ACTION_ID_GET_FILE_INFO = "get_file_info"
    ACTION_ID_BLOCK_HASH = "block_hash"
    ACTION_ID_UNBLOCK_HASH = "unblock_hash"
    ACTION_ID_TERMINATE_PROCESS = "terminate_process"
    ACTION_ID_LIST_CONNECTIONS = "list_connections"
    ACTION_ID_GET_LICENSE = "get_license"
    ACTION_ID_ON_POLL = "on_poll"
    ACTION_ID_PUT_FILE = "put_file"
    ACTION_ID_RUN_COMMAND = "run_command"
    ACTION_ID_EXECUTE_PROGRAM = "execute_program"
    ACTION_ID_RESET_SESSION = "reset_session"
    ACTION_ID_MEMORY_DUMP = "memory_dump"

    MAGIC_FORMATS = [
        (re.compile("^PE.* Windows"), ["pe file"], ".exe"),
        (re.compile("^MS-DOS executable"), ["pe file"], ".exe"),
        (re.compile("^PDF "), ["pdf"], ".pdf"),
        (re.compile("^MDMP crash"), ["process dump"], ".dmp"),
        (re.compile("^Macromedia Flash"), ["flash"], ".flv"),
        (re.compile("^tcpdump capture"), ["pcap"], ".pcap"),
    ]

    def __init__(self):
        # Call the BaseConnectors init first
        super().__init__()

        self._base_url = None
        self._api_token = None
        self._state_file_path = None
        self._state = {}

    def finalize(self):
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def initialize(self):
        self._state = self.load_state()
        config = self.get_config()

        # Fetching the Python major version
        try:
            self._python_version = int(sys.version_info[0])
        except:
            return self.set_status(phantom.APP_ERROR, "Error occurred while getting the Phantom server's Python major version.")

        # Base URL
        self._base_url = config[CARBONBLACK_JSON_DEVICE_URL].rstrip("/")
        self._api_token = config[CARBONBLACK_JSON_API_TOKEN]
        self._headers = {"X-Auth-Token": self._api_token, "Content-Type": "application/json"}
        self._rest_uri = f"{self._base_url}/api"

        return phantom.APP_SUCCESS

    def _get_error_message_from_exception(self, e):
        """This method is used to get appropriate error message from the exception.
        :param e: Exception object
        :return: error message
        """

        error_msg = CARBONBLACK_ERROR_MSG
        error_code = CARBONBLACK_ERROR_CODE_MSG
        try:
            if hasattr(e, "args"):
                if len(e.args) > 1:
                    error_code = e.args[0]
                    error_msg = e.args[1]
                elif len(e.args) == 1:
                    error_msg = e.args[0]
        except:
            error_code = CARBONBLACK_ERROR_CODE_MSG
            error_msg = CARBONBLACK_ERROR_MSG

        try:
            error_msg = self._handle_py_ver_compat_for_input_str(error_msg)
        except TypeError:
            error_msg = CARBONBLACK_UNICODE_DAMMIT_TYPE_ERROR_MSG
        except:
            error_msg = CARBONBLACK_ERROR_MSG

        return f"Error Code: {error_code}. Error Message: {error_msg}"

    def _handle_py_ver_compat_for_input_str(self, input_str):
        """
        This method returns the encoded|original string based on the Python version.

        :param input_str: Input string to be processed
        :return: input_str (Processed input string based on following logic 'input_str - Python 3; encoded input_str - Python 2')
        """

        try:
            if input_str and self._python_version == 2:
                input_str = UnicodeDammit(input_str).unicode_markup.encode("utf-8")
        except:
            self.debug_print("Error occurred while handling python 2to3 compatibility for the input string")

        return input_str

    def _validate_integer(self, action_result, parameter, key, allow_zero=False):
        if parameter is not None:
            try:
                if not float(parameter).is_integer():
                    return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_INTEGER_VALUE.format(msg="", param=key)), None

                parameter = int(parameter)
            except:
                return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_INTEGER_VALUE.format(msg="", param=key)), None

            if parameter < 0:
                return action_result.set_status(
                    phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_INTEGER_VALUE.format(msg="non-negative", param=key)
                ), None
            if not allow_zero and parameter == 0:
                return action_result.set_status(
                    phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_INTEGER_VALUE.format(msg="non-zero positive", param=key)
                ), None

        return phantom.APP_SUCCESS, parameter

    def _normalize_reply(self, reply):
        try:
            soup = BeautifulSoup(reply, "html.parser")
            return soup.text
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            self.debug_print(f"Handled exception: {error_message}")
            return "Unparsable Reply. Please see the log files for the response text."

    def _make_rest_call(
        self,
        endpoint,
        action_result,
        method="get",
        params={},
        headers=None,
        files=None,
        data=None,
        parse_response_json=True,
        additional_succ_codes={},
    ):
        """treat_status_code is a way in which the caller tells the function, 'if you get a status code present in this dictionary,
        then treat this as a success and just return be this value'
        This was added to take care os changes Carbon Black made to their code base,
        with minimal amount of changes to the app _and_ to keep pylint happy.
        """

        url = f"{self._rest_uri}{endpoint}"
        self.save_progress(url)

        if not headers:
            headers = {}
        headers.update(self._headers)

        if files is not None:
            del headers["Content-Type"]

        config = self.get_config()

        request_func = getattr(requests, method)

        if not request_func:
            return (action_result.set_status(phantom.APP_ERROR, f"Invalid method call: {method} for requests module"), None)

        if data is not None:
            data = json.dumps(data)

        try:
            r = request_func(url, headers=headers, params=params, files=files, data=data, verify=config[phantom.APP_JSON_VERIFY])
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return (action_result.set_status(phantom.APP_ERROR, f"REST Api to server failed. {error_message}"), None)

        # It's ok if r.text is None, dump that
        # action_result.add_debug_data({'r_text': r.text if r else 'r is None'})

        if r.status_code in additional_succ_codes:
            response = additional_succ_codes[r.status_code]
            return (phantom.APP_SUCCESS, response if response is not None else r.text)

        # Look for errors
        if not r.ok:  # pylint: disable=E1101
            # return (action_result.set_status(phantom.APP_ERROR, "REST Api Call returned error, status_code: {0}, data: {1}".format(
            # r.status_code, self._normalize_reply(r.text))), r.text)

            return (action_result.set_status(phantom.APP_ERROR, f"REST Api Call returned error, status_code: {r.status_code}"), None)

        resp_json = None

        if parse_response_json:
            # Try a json parse
            try:
                resp_json = r.json()
            except:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR,
                        f"Unable to parse response as a JSON status_code: {r.status_code}, data: {self._normalize_reply(r.text)}",
                    ),
                    None,
                )
        else:
            resp_json = r

        return (phantom.APP_SUCCESS, resp_json)

    def _get_system_info_from_cb(self, ip_hostname, action_result, sensor_id=None):
        endpoint = "/v1/sensor"
        query_parameters = None

        if sensor_id is None:
            # first get the data, use ip if given
            if phantom.is_ip(ip_hostname):
                query_parameters = {"ip": ip_hostname}
            else:
                query_parameters = {"hostname": ip_hostname}
        else:
            endpoint = f"{endpoint}/{sensor_id}"

        ret_val, sensors = self._make_rest_call(endpoint, action_result, params=query_parameters, additional_succ_codes={204: []})

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({CARBONBLACK_JSON_TOTAL_ENDPOINTS: 0})

        if not sensors:
            return action_result.set_status(phantom.APP_SUCCESS)

        if type(sensors) != list:
            sensors = [sensors]

        action_result.update_summary({CARBONBLACK_JSON_TOTAL_ENDPOINTS: len(sensors)})

        for sensor in sensors:
            action_result.add_data(sensor)
            if "network_adapters" not in sensor:
                continue

            adapters = sensor["network_adapters"].split("|")

            if not adapters:
                continue

            ips = []
            for adapter in adapters:
                ip = adapter.split(",")[0].strip()
                if not ip:
                    continue
                ips.append(ip)

            sensor[CARBONBLACK_JSON_IPS] = ",".join(ips)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_connections_for_process(self, params, action_result):
        """Get a list of all processes matching the search parameters"""
        """ This is the same API call that run query uses but it's a bit different
          " The search parameters are URL parameters instead of posted in because of reasons
          " This function will always get the entire list of results, no matter how large,
          "  so be careful.
          "
          " params sent for searching by pid/process_name
          " params = {'cb.q.process_name/pid': process_name/pid,
          "           ['cb.q.hostname': hostname]}
          "
          " params sent for searching by id
          " params = {'cb.q.id': carbonblack_id}
        """

        # get a list of all processes at an endpoint
        # First get a call with 0 results go get the total number of processes
        params["rows"] = 0
        ret_val, json_resp = self._make_rest_call("/v1/process", action_result, params=params)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, "Error finding processes")

        if json_resp["total_results"] == 0:
            return action_result.set_status(phantom.APP_SUCCESS, "No connections found")
        # Make same call to get all of the processes
        params["rows"] = json_resp["total_results"]
        ret_val, json_resp = self._make_rest_call("/v1/process", action_result, params=params)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        process_list = json_resp["results"]

        if len(process_list) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, "No processes found")

        # Now we need to get the connections for each process
        total_processes = 0
        total_processes_to_process = len(process_list)
        printed_message = ""
        for i, process in enumerate(process_list):
            curr_message = CARBONBLACK_FINISHED_PROCESSING.format(float(i) / float(total_processes_to_process))

            if curr_message != printed_message:
                self.send_progress(curr_message)
                printed_message = curr_message

            # Process has no connections, don't need to waste time on rest call
            if process["netconn_count"] == 0:
                continue
            total_processes += 1
            self._get_connections_for_process_event(process.get("id"), process.get("segment_id"), action_result)

        action_result.update_summary({"total_processes": total_processes})
        action_result.update_summary({"total_connections": len(action_result.get_data())})

        if len(action_result.get_data()) == 0:
            return action_result.set_status(phantom.APP_SUCCESS, "No connections found")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully retrieved connections for process")

    def _get_connections_for_process_event(self, cb_id, segment_id, action_result):
        """Get a process event and parse netconn"""
        # What are the rest? Who knows
        protocol_dict = {"6": "TCP", "17": "UDP"}

        if cb_id is None or segment_id is None:
            # Something has gone seriously wrong, don't panic
            return

        endpoint = f"/v1/process/{cb_id}/{segment_id}/event"

        ret_val, event_json = self._make_rest_call(endpoint, action_result, params={"cb.legacy_5x_mode": False})
        if phantom.is_fail(ret_val):
            return

        if "process" not in event_json or "netconn_complete" not in event_json["process"]:
            return

        netconns = event_json["process"]["netconn_complete"]
        pid = event_json["process"]["process_pid"]
        name = event_json["process"]["process_name"]
        hostname = event_json["process"]["hostname"]
        connection_dict = {}

        # connection_dict['process_name'] = name
        # connection_dict['pid'] = pid
        # connection_dict['hostname'] = hostname
        # connection_dict['process_id'] = cb_id
        connection_dict["connections"] = []

        connection = {}
        connection["process_name"] = name
        connection["pid"] = pid
        connection["hostname"] = hostname
        connection["carbonblack_process_id"] = cb_id

        for netconn in netconns:
            fields = netconn.split("|")
            connection["event_time"] = fields[0]
            connection["ip_addr"] = self._to_ip(fields[1])
            connection["port"] = fields[2]
            connection["protocol"] = protocol_dict.get(fields[3], fields[3])
            connection["domain"] = fields[4]
            connection["direction"] = "outbound" if fields[5] == "true" else "inbound"
            action_result.add_data(connection.copy())
            # connection_dict['connections'].append(connection)
        # action_result.add_data(connection_dict)
        return

    def _to_ip(self, input_ip):
        """Convert 32 bit unsigned int to IP"""
        if not input_ip:
            return ""

        # Convert to an unsigned int
        try:
            input_ip = int(input_ip)
        except:
            return ""
        input_ip = ctypes.c_uint32(input_ip).value
        # long(input_ip) & 0xffffffff
        # input_ip = long(input_ip)
        return socket.inet_ntoa(struct.pack("!L", input_ip))

    def _get_existing_live_session_id(self, sensor_id, action_result):
        """Uses "GET /session" to check for existing sessions with the specified sensor_id
        " and a status of "active" or "pending". Returns the first found session or None.
        """
        # get a list of all the sessions
        ret_val, sessions = self._make_rest_call("/v1/cblr/session", action_result)

        if phantom.is_fail(ret_val):
            return None

        # get sessions belonging to the sensor we are interested in
        sessions = [x for x in sessions if x["sensor_id"] == int(sensor_id)]

        if not sessions:
            return None

        valid_states = ["active", "pending"]

        session_ids = [x["id"] for x in sessions if (x["status"] in valid_states)]

        if not session_ids:
            return None

        return session_ids[0]

    def _get_live_session_id(self, sensor_id, action_result):
        # Check for existing live sessions with the endpoint
        self.save_progress("Checking for existing live sessions that ca be reused.")
        session_id = self._get_existing_live_session_id(sensor_id, action_result)

        if not session_id:
            self.save_progress("No existing session was found; trying to start a new live session")

            # Make a new live session with the endpoint
            data = {"sensor_id": int(sensor_id)}
            ret_val, resp = self._make_rest_call("/v1/cblr/session", action_result, data=data, method="post")

            if phantom.is_fail(ret_val) or resp is None:
                action_result.append_to_message("Failed to create a new live session.")
                return (action_result.get_status(), None)

            session_id = resp.get("id")

            if not session_id:
                return (
                    action_result.set_status(phantom.APP_ERROR, "Did not get a session id in the response from a new session creation"),
                    None,
                )

        # Now we either have a newly created session id, an existing pending session id, or an existing active session id
        status = "unknown"

        tries = 0
        url = f"/v1/cblr/session/{session_id}"

        while (status != "active") and (tries <= MAX_POLL_TRIES):
            try:
                self.send_progress("Getting session id for sensor: {} {}".format(sensor_id, ".".join(["" for x in xrange(tries + 1)])))
            except NameError:
                # Python 3, xrange renamed to range
                self.send_progress("Getting session id for sensor: {} {}".format(sensor_id, ".".join(["" for x in range(tries + 1)])))
            time.sleep(CARBONBLACK_SLEEP_SECS)

            # try to get the status of the live session
            ret_val, resp = self._make_rest_call(url, action_result)

            tries += 1

            if phantom.is_fail(ret_val):
                if resp and f"Session {session_id} not found" not in resp:
                    continue
                else:
                    return (action_result.set_status(phantom.APP_ERROR, "Unable to find session on the server"), None)

            status = resp.get("status")

            if status == "active":
                break

        if status != "active":
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_POLL_TIMEOUT.format(max_tries=MAX_POLL_TRIES)), None)

        return (phantom.APP_SUCCESS, session_id)

    def _execute_live_session_command(self, session_id, action_result, command, additional_data={}):
        self.save_progress(f"Executing command {command}")

        # now execute a command to get the process list
        data = {"session_id": session_id, "name": command}
        data.update(additional_data)

        url = f"/v1/cblr/session/{session_id}/command"

        ret_val, resp = self._make_rest_call(url, action_result, data=data, method="post")

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), resp)

        command_id = resp.get("id")

        if command_id is None:
            return (action_result.set_status(phantom.APP_ERROR, "Did not get the command id from the server"), resp)

        # Now make the rest call to wait for the command to finish
        url = f"{url}/{command_id}"

        self.save_progress("Waiting for command completion")
        ret_val, resp = self._make_rest_call(url, action_result, params={"wait": "true"})

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), resp)

        result_code = resp.get("result_code")

        if result_code != 0:
            msg = CARBONBLACK_COMMAND_FAILED.format(
                command=command, code=resp.get("result_code", "Not Specified"), desc=resp.get("result_desc", "Not Specified")
            )
            if result_code == 2147942480:
                msg = f"{CARBONBLACK_ERROR_FILE_EXISTS}{msg}"
            elif result_code == 2147942403:
                msg = f"{CARBONBLACK_ERROR_INVALID_PATH} {msg}"
            elif result_code == 2147942417:
                msg = f"{CARBONBLACK_ERROR_INVALID_DEST_FILE} {msg}"
            return (action_result.set_status(phantom.APP_ERROR, msg), resp)

        return (phantom.APP_SUCCESS, resp)

    def _get_process_list(self, sensor_id, action_result):
        if sensor_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Sensor ID not found")

        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress(f"Got live session ID: {session_id}")

        data = {"session_id": session_id, "object": ""}
        ret_val, resp = self._execute_live_session_command(session_id, action_result, "process list", data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        processes = resp.get("processes")

        if processes is None:
            return action_result.set_status(phantom.APP_ERROR, "Processes information missing from server response")

        for process in processes:
            try:
                name = process["path"].split("\\")[-1]
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                self.debug_print(f"Handled exceptions: {error_message}")
                name = ""
            process["name"] = name
            action_result.add_data(process)

        action_result.update_summary({"total_processes": len(processes)})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _terminate_process_on_endpoint(self, sensor_id, action_result, pid):
        if sensor_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Sensor ID not found")

        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress(f"Got live session ID: {session_id}")

        data = {"object": pid}

        ret_val, resp = self._execute_live_session_command(session_id, action_result, "kill", data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp)

        try:
            action_result.update_summary({"status": resp["status"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def _terminate_process(self, param):
        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)

        action_result = self.add_action_result(ActionResult(param))

        ret_val, pid = self._validate_integer(self, param.get(CARBONBLACK_JSON_PID), CARBONBLACK_JSON_PID, True)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, self.get_status_message())

        if not ip_hostname and sensor_id is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Neither {phantom.APP_JSON_IP_HOSTNAME} nor {CARBONBLACK_JSON_SENSOR_ID} specified. Please specify at-least one of them",
            )

        if sensor_id is not None:
            ret_val, sensor_id = self._validate_integer(action_result, sensor_id, CARBONBLACK_JSON_SENSOR_ID, True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self._terminate_process_on_endpoint(sensor_id, action_result, pid)
            return action_result.get_status()

        ret_val = self._get_system_info_from_cb(ip_hostname, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        systems = action_result.get_data()

        self.save_progress(f"Got {len(systems)} systems")

        if not systems:
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_NO_ENDPOINTS.format(ip_hostname))

        systems = [x for x in systems if x.get("status", "Offline") == "Online"]

        if len(systems) > 1:
            systems_error = "<ul>"

            for system in systems:
                systems_error = "{}{}".format(systems_error, "<li>{}</li>".format(system.get("computer_name")))

            systems_error = f"{systems_error}</ul>"
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_MSG_MORE_THAN_ONE.format(systems_error=systems_error))

        system = systems[0]

        self._terminate_process_on_endpoint(system.get("id"), action_result, pid)

        return phantom.APP_SUCCESS

    def _list_processes(self, param):
        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)

        action_result = ActionResult(param)

        if not ip_hostname and sensor_id is None:
            self.add_action_result(action_result)
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Neither {phantom.APP_JSON_IP_HOSTNAME} nor {CARBONBLACK_JSON_SENSOR_ID} specified. Please specify at-least one of them",
            )

        if sensor_id is not None:
            self.add_action_result(action_result)
            ret_val, sensor_id = self._validate_integer(action_result, sensor_id, CARBONBLACK_JSON_SENSOR_ID, True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self._get_process_list(sensor_id, action_result)
            return action_result.get_status()

        ret_val = self._get_system_info_from_cb(ip_hostname, action_result)

        if phantom.is_fail(ret_val):
            self.add_action_result(action_result)
            return action_result.get_status()

        systems = action_result.get_data()

        self.save_progress(f"Got {len(systems)} systems")

        if not systems:
            self.add_action_result(action_result)
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_NO_ENDPOINTS.format(ip_hostname))

        for system in systems:
            action_result = self.add_action_result(ActionResult({phantom.APP_JSON_IP_HOSTNAME: system.get("computer_name")}))
            if system.get("status") != "Online":
                action_result.set_status(phantom.APP_ERROR, "Ignoring Offline Endpoint")
                continue
            self._get_process_list(system.get("id"), action_result)

        return phantom.APP_SUCCESS

    def _get_file_summary(self, sample_hash, action_result=ActionResult(), additional_succ_codes={}):
        # get the file summary from the CB server
        url = f"/v1/binary/{sample_hash}/summary"

        ret_val, response = self._make_rest_call(url, action_result, additional_succ_codes=additional_succ_codes)

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, response)

    def _download_file_to_vault(self, action_result, file_summary, sample_hash):
        url = f"/v1/binary/{sample_hash}"

        ret_val, response = self._make_rest_call(url, action_result, parse_response_json=False)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()

        if hasattr(Vault, "get_vault_tmp_dir"):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = "/vault/tmp"

        local_dir = f"{temp_dir}/{guid}"
        self.save_progress(f"Using {temp_dir} directory: {guid}")

        try:
            os.makedirs(local_dir)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Unable to create temporary folder {temp_dir}. {error_message}")

        zip_file_path = f"{local_dir}/{sample_hash}.zip"

        # open and download the file
        with open(zip_file_path, "wb") as f:
            f.write(response.content)

        # Open the zip file
        zf = zipfile.ZipFile(zip_file_path)

        # zipped_file_names = zf.namelist()
        # zipped_file_names = zipped_file_names

        try:
            # extract them
            zf.extractall(local_dir)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Unable to extract the zip file. {error_message}")

        # create the file_path
        file_path = f"{local_dir}/filedata"

        contains = []
        file_ext = ""
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if not file_ext:
                    file_ext = extension

        file_name = f"{sample_hash}{file_ext}"

        observed_filename = file_summary.get("observed_filename")
        if observed_filename:
            try:
                file_name = observed_filename[0].split("\\")[-1]
            except:
                pass

        # move the file to the vault
        success, message, vault_id = ph_rules.vault_add(
            container=self.get_container_id(), file_location=file_path, file_name=file_name, metadata={"contains": contains}
        )
        curr_data = action_result.get_data()[0]
        curr_data[CARBONBLACK_JSON_FILE_DETAILS] = file_summary

        if success:
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_id
            curr_data[phantom.APP_JSON_NAME] = file_name
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if contains:
                summary.update({"file_type": ",".join(contains)})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERROR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(message)

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return phantom.APP_ERROR

    def _save_file_to_vault(self, action_result, response, sample_hash):
        # Create a tmp directory on the vault partition
        guid = uuid.uuid4()

        if hasattr(Vault, "get_vault_tmp_dir"):
            temp_dir = Vault.get_vault_tmp_dir()
        else:
            temp_dir = "/vault/tmp"

        local_dir = f"{temp_dir}/{guid}"
        self.save_progress(f"Using {temp_dir} directory: {guid}")

        try:
            os.makedirs(local_dir)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Unable to create temporary folder {temp_dir}. {error_message}")

        zip_file_path = f"{local_dir}/{sample_hash}.zip"

        # open and download the file
        with open(zip_file_path, "wb") as f:
            f.write(response.content)

        # Open the zip file
        zf = zipfile.ZipFile(zip_file_path)

        # zipped_file_names = zf.namelist()
        # zipped_file_names = zipped_file_names

        try:
            # extract them
            zf.extractall(local_dir)
        except Exception as e:
            error_message = self._get_error_message_from_exception(e)
            return action_result.set_status(phantom.APP_ERROR, f"Unable to extract the zip file. {error_message}")

        # create the file_path
        file_path = f"{local_dir}/filedata"

        contains = []
        file_ext = ""
        magic_str = magic.from_file(file_path)
        for regex, cur_contains, extension in self.MAGIC_FORMATS:
            if regex.match(magic_str):
                contains.extend(cur_contains)
                if not file_ext:
                    file_ext = extension

        file_name = f"{sample_hash}{file_ext}"

        # now try to get info about the file from CarbonBlack
        ret_val, file_summary = self._get_file_summary(sample_hash)

        if phantom.is_success(ret_val):
            observed_filename = file_summary.get("observed_filename")
            if observed_filename:
                try:
                    file_name = observed_filename[0].split("\\")[-1]
                except:
                    pass

        # move the file to the vault
        success, message, vault_id = ph_rules.vault_add(
            container=self.get_container_id(), file_location=file_path, file_name=file_name, metadata={"contains": contains}
        )
        curr_data = action_result.add_data({})
        curr_data[CARBONBLACK_JSON_FILE_DETAILS] = file_summary

        if success:
            curr_data[phantom.APP_JSON_VAULT_ID] = vault_id
            curr_data[phantom.APP_JSON_NAME] = file_name
            wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
            summary = {x: curr_data[x] for x in wanted_keys}
            if contains:
                summary.update({"file_type": ",".join(contains)})
            summary.update({CARBONBLACK_JSON_FILE_CB_URL: f"{self._base_url}/#/binary/{sample_hash}"})
            action_result.update_summary(summary)
            action_result.set_status(phantom.APP_SUCCESS)
        else:
            action_result.set_status(phantom.APP_ERROR, phantom.APP_ERROR_FILE_ADD_TO_VAULT)
            action_result.append_to_message(message)

        # remove the /tmp/<> temporary directory
        shutil.rmtree(local_dir)

        return action_result.get_status()

    def _run_command(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, sensor_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SENSOR_ID), CARBONBLACK_JSON_SENSOR_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        command = param["command"].lower()
        try:
            data = json.loads(param["data"])
        except:
            return action_result.set_status(
                phantom.APP_ERROR, "Error while parsing json string provided in data parameter. Please provide a valid JSON string."
            )

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress(f"Got live session ID: {session_id}")

        ret_val, resp = self._execute_live_session_command(session_id, action_result, command, data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp)

        try:
            action_result.update_summary({"status": resp["status"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, "Run command successful")

    def _execute_program(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, sensor_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SENSOR_ID), CARBONBLACK_JSON_SENSOR_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data = {"object": param["entire_executable_path"], "wait": param.get("wait", False)}
        if param.get("working_directory"):
            data.update({"working_directory": param.get("working_directory")})
        if param.get("output_file"):
            data.update({"output_file": param.get("output_file")})

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress(f"Got live session ID: {session_id}")

        ret_val, resp = self._execute_live_session_command(session_id, action_result, "create process", data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp)

        try:
            action_result.update_summary({"status": resp["status"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, "Program executed successfully")

    def _memory_dump(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, sensor_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SENSOR_ID), CARBONBLACK_JSON_SENSOR_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        data = {"object": param["destination_path"], "compress": param.get("compress", False)}

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress(f"Got live session ID: {session_id}")

        ret_val, resp = self._execute_live_session_command(session_id, action_result, "memdump", data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp)

        try:
            action_result.update_summary({"status": resp["status"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, "Memory dump successful")

    def _put_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        vault_id = param[CARBONBLACK_JSON_VAULT_ID]
        destination = param[CARBONBLACK_JSON_DESTINATION_PATH]
        ret_val, sensor_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SENSOR_ID), CARBONBLACK_JSON_SENSOR_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # First get a session id
        ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not session_id:
            return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

        self.save_progress(f"Got live session ID: {session_id}")

        # Upload File to Server
        _, _, vault_meta_info = ph_rules.vault_info(container_id=self.get_container_id(), vault_id=vault_id)
        if not vault_meta_info:
            self.debug_print(f"Error while fetching meta information for vault ID: {vault_id}")
            return action_result.set_status(phantom.APP_ERROR, "Could not find specified vault ID in vault")

        vault_meta_info = list(vault_meta_info)
        vault_path = vault_meta_info[0]["path"]

        url = f"/v1/cblr/session/{session_id}/file"
        data = {"file": open(vault_path, "rb")}

        ret_val, response = self._make_rest_call(url, action_result, files=data, method="post")

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        # Get the file_id from the Upload File to Server response
        file_id = response.get("id")

        # Post the file to the host
        data = {"object": destination, "file_id": file_id}

        ret_val, resp = self._execute_live_session_command(session_id, action_result, "put file", data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(resp)

        try:
            action_result.update_summary({"status": resp["status"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, "Put file successful")

    def _get_file(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param.get(CARBONBLACK_JSON_HASH)

        if sample_hash:
            self.save_progress("Querying Carbon Black Response for hash")
            url = f"/v1/binary/{sample_hash}"

            ret_val, response = self._make_rest_call(
                url, action_result, parse_response_json=False, additional_succ_codes={404: CARBONBLACK_MSG_FILE_NOT_FOUND}
            )

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if response == CARBONBLACK_MSG_FILE_NOT_FOUND:
                return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_MSG_FILE_NOT_FOUND)

            return self._save_file_to_vault(action_result, response, sample_hash)
        else:
            self.save_progress("Querying Carbon Black Response for file")

            file_source = param.get("file_source")

            ret_val, offset = self._validate_integer(action_result, param.get("offset"), "offset", True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val, get_count = self._validate_integer(action_result, param.get("get_count"), "get_count", True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            ret_val, sensor_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SENSOR_ID), CARBONBLACK_JSON_SENSOR_ID, True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not file_source:
                return action_result.set_status(phantom.APP_ERROR, "Please provide either hash or file_source parameter value")
            elif not sensor_id:
                return action_result.set_status(
                    phantom.APP_ERROR, "Please provide sensor_id if file is fetched using file_source parameter value"
                )

            # First get a session id
            ret_val, session_id = self._get_live_session_id(sensor_id, action_result)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            if not session_id:
                return action_result.set_status(phantom.APP_ERROR, "Invalid session id")

            self.save_progress(f"Got live session ID: {session_id}")

            data = {"object": file_source}
            if offset:
                data.update({"offset": offset})
            if get_count:
                data.update({"get_count": get_count})

            # Get file and file id
            ret_val, response = self._execute_live_session_command(session_id, action_result, "get file", data)

            if phantom.is_fail(ret_val):
                return action_result.get_status()

            file_id = response.get("file_id")

            # Download file from server
            url = f"/v1/cblr/session/{session_id}/file/{file_id}/content"

            response = requests.get(f"{self._rest_uri}{url}", headers={"X-Auth-Token": self._api_token}, stream=True, verify=False)  # nosemgrep

            guid = uuid.uuid4()

            if hasattr(Vault, "get_vault_tmp_dir"):
                temp_dir = Vault.get_vault_tmp_dir()
            else:
                temp_dir = "/vault/tmp"

            local_dir = f"{temp_dir}/{guid}"
            self.save_progress(f"Using {temp_dir} directory: {guid}")

            try:
                os.makedirs(local_dir)
            except Exception as e:
                error_message = self._get_error_message_from_exception(e)
                return action_result.set_status(phantom.APP_ERROR, f"Unable to create temporary folder {temp_dir}. {error_message}")

            safe_char_file_source = six.moves.urllib.parse.quote_plus(file_source)
            zip_file_path = f"{local_dir}/{safe_char_file_source}.zip"

            try:
                # open and download the file
                with open(zip_file_path, "wb") as fd:
                    for chunk in response.iter_content(chunk_size=128):
                        fd.write(chunk)
            except:
                return action_result.set_status(phantom.APP_ERROR, "Error occurred while downloading the file")

            file_name = file_source.replace("\\\\", "\\")

            success, message, vault_id = ph_rules.vault_add(container=self.get_container_id(), file_location=zip_file_path, file_name=file_name)

            curr_data = action_result.add_data({"session_id": session_id, "file_id": file_id})

            if success:
                curr_data[phantom.APP_JSON_VAULT_ID] = vault_id
                curr_data[phantom.APP_JSON_NAME] = file_name
                wanted_keys = [phantom.APP_JSON_VAULT_ID, phantom.APP_JSON_NAME]
                summary = {x: curr_data[x] for x in wanted_keys}
                action_result.update_summary(summary)
                action_result.set_status(phantom.APP_SUCCESS)
            else:
                action_result.set_status(phantom.APP_ERROR, phantom.APP_ERROR_FILE_ADD_TO_VAULT)
                action_result.append_to_message(message)

            # remove the /tmp/<> temporary directory
            shutil.rmtree(local_dir)

            return action_result.get_status()

    def _get_file_info(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))

        sample_hash = param[CARBONBLACK_JSON_HASH]

        # now try to get info about the file from CarbonBlack
        ret_val, file_summary = self._get_file_summary(sample_hash, action_result, additional_succ_codes={404: CARBONBLACK_MSG_FILE_NOT_FOUND})

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if file_summary == CARBONBLACK_MSG_FILE_NOT_FOUND:
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_MSG_FILE_NOT_FOUND)

        curr_data = action_result.add_data({})
        curr_data[CARBONBLACK_JSON_FILE_DETAILS] = file_summary

        summary = {
            "name": file_summary.get("original_filename"),
            "os_type": file_summary.get("os_type"),
            "architecture": "64 bit" if file_summary.get("is_64bit", False) else "32 bit",
            "size": file_summary.get("orig_mod_len"),
            CARBONBLACK_JSON_FILE_CB_URL: f"{self._base_url}/#/binary/{sample_hash}",
        }

        action_result.update_summary(summary)

        download = param.get(CARBONBLACK_JSON_DOWNLOAD, False)

        if not download:
            return action_result.set_status(phantom.APP_SUCCESS)

        return self._download_file_to_vault(action_result, file_summary, sample_hash)

    def _sync_sensor_events(self, sensor_id, action_result):
        """Called when a sensor_id has been determined and the events need to be flushed to the server"""

        if sensor_id is None:
            return action_result.set_status(phantom.APP_ERROR, "Sensor ID not found")

        ret_val, sensor = self._make_rest_call(f"/v1/sensor/{sensor_id}", action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not sensor or "status" not in sensor or sensor["status"] != "Online":
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find valid sensor to sync"), None)

        # any time in the future should work, but the official API uses now + 24h, so we will use that as well
        # the timezone is hard-coded to match what was seen in the web interface
        updated_sensor = dict()
        updated_sensor["event_log_flush_time"] = (datetime.datetime.now() + datetime.timedelta(days=1)).strftime("%a, %d %b %Y %H:%M:%S GMT")
        if sensor.get("group_id"):
            updated_sensor["group_id"] = sensor["group_id"]
        else:
            self.debug_print(CARBONBLACK_GROUP_ID_MSG)

        ret_val, body = self._make_rest_call(
            f"/v1/sensor/{sensor_id}", action_result, data=updated_sensor, method="put", additional_succ_codes={204: []}
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_SYNC_EVENTS)

    def _is_valid_integer(self, input_value):
        try:
            if not str(input_value).isdigit():
                raise ValueError
        except ValueError:
            return False
        return True

    def _sync_events(self, param):
        """Force the sensor with the given sensor_id or ip_hostname to flush all its recorded events to the server.
        " If the sensor_id is specified it will be used, otherwise the ip_hostname will be used to query for the sensor_id
        " The flush is done by writing a future datetime to the sensor's event_log_flush_time and PUTing the new sensor data
        """

        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        sensor_id = param.get(CARBONBLACK_JSON_SENSOR_ID)

        if not ip_hostname and sensor_id is None:
            action_result = self.add_action_result(ActionResult(param))
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Neither {phantom.APP_JSON_IP_HOSTNAME} nor {CARBONBLACK_JSON_SENSOR_ID} specified. Please specify at-least one of them",
            )

        if sensor_id is not None:
            # set the param to _only_ contain the sensor_id, since that's the only one we are using
            action_result = self.add_action_result(ActionResult({CARBONBLACK_JSON_SENSOR_ID: sensor_id}))

            ret_val, sensor_id = self._validate_integer(action_result, sensor_id, CARBONBLACK_JSON_SENSOR_ID, True)
            if phantom.is_fail(ret_val):
                return action_result.get_status()

            self._sync_sensor_events(sensor_id, action_result)
            return action_result.get_status()

        sys_info_ar = ActionResult(param)

        ret_val = self._get_system_info_from_cb(ip_hostname, sys_info_ar)

        if phantom.is_fail(ret_val):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = sys_info_ar.get_data()

        self.save_progress(f"Got {len(systems)} systems")

        if not systems:
            self.add_action_result(sys_info_ar)
            return sys_info_ar.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_NO_ENDPOINTS.format(ip_hostname))

        for system in systems:
            action_result = self.add_action_result(ActionResult({phantom.APP_JSON_IP_HOSTNAME: system.get("computer_name")}))
            if system.get("status") != "Online":
                action_result.set_status(phantom.APP_ERROR, "Ignoring Offline Endpoint")
                continue
            self._sync_sensor_events(system.get("id"), action_result)

        return phantom.APP_SUCCESS

    def _get_system_info(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME)
        ret_val, sensor_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SENSOR_ID), CARBONBLACK_JSON_SENSOR_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if not ip_hostname and sensor_id is None:
            return action_result.set_status(
                phantom.APP_ERROR,
                f"Neither {phantom.APP_JSON_IP_HOSTNAME} nor {CARBONBLACK_JSON_SENSOR_ID} specified. Please specify at-least one of them",
            )

        ret_val = self._get_system_info_from_cb(ip_hostname, action_result, sensor_id)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        systems = action_result.get_data()

        self.save_progress(f"Got {len(systems)} systems")

        if not systems:
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_NO_ENDPOINTS.format(ip_hostname))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _quarantine_device(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]

        ret_val, response = self._set_isolate_state(ip_hostname, action_result, True)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            action_result.update_summary({"status": "success"})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_QUARANTINE)

    def _unquarantine_device(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ip_hostname = param[phantom.APP_JSON_IP_HOSTNAME]

        ret_val, response = self._set_isolate_state(ip_hostname, action_result, False)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            action_result.update_summary({"status": "success"})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_UNQUARANTINE)

    def _set_isolate_state(self, ip_hostname, action_result, state=True):
        if phantom.is_ip(ip_hostname):
            query_parameters = {"ip": ip_hostname}
        else:
            query_parameters = {"hostname": ip_hostname}

        # make a rest call to get the sensors
        ret_val, sensors = self._make_rest_call("/v1/sensor", action_result, params=query_parameters, additional_succ_codes={204: []})

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        if not sensors:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find endpoint, sensor list was empty"), None)

        sensors = [x for x in sensors if x.get("status") == "Online"]

        if not sensors:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find an online endpoint, sensor list was empty"), None)

        num_endpoints = len(sensors)

        if num_endpoints > 1:
            # add the sensors found in the action_result
            self._add_sensor_info_to_result(sensors, action_result)
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_MULTI_ENDPOINTS.format(num_endpoints=num_endpoints)), None)

        # get the id, of the 1st one, that's what we will be working on
        data = sensors[0]

        if "id" not in data:
            return (action_result.set_status(phantom.APP_ERROR, "Unable to find endpoint id in response"), None)

        endpoint_id = data["id"]

        # set the isolation status
        updated_data = dict()
        updated_data["network_isolation_enabled"] = state
        if data.get("group_id"):
            updated_data["group_id"] = data["group_id"]
        else:
            self.debug_print(CARBONBLACK_GROUP_ID_MSG)

        # make a rest call to set the endpoint state
        ret_val, response = self._make_rest_call(
            f"/v1/sensor/{endpoint_id}",
            action_result,
            method="put",
            data=updated_data,
            params=query_parameters,
            parse_response_json=False,
            additional_succ_codes={204: []},
        )

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, sensors)

    def _unblock_hash(self, param):
        action_result = self.add_action_result(ActionResult(param))

        unblock_hash = param[CARBONBLACK_JSON_HASH]

        url = f"/v1/banning/blacklist/{unblock_hash}"

        # make a rest call to unblock the hash
        ret_val, response = self._make_rest_call(
            url, action_result, method="delete", parse_response_json=False, additional_succ_codes={409: None}
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if "does not exist" in response:
            return action_result.set_status(phantom.APP_ERROR, "Supplied MD5 is not currently banned/blocked.")

        try:
            action_result.update_summary({"status": "success"})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_UNBLOCK if (not response or type(response) != str) else response)

    def _get_license(self, param):
        action_result = self.add_action_result(ActionResult(param))

        url = "/v1/license"

        # make a rest call
        ret_val, response = self._make_rest_call(url, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.add_data(response)

        try:
            action_result.update_summary({"license_valid": response["license_valid"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS)

    def _block_hash(self, param):
        action_result = self.add_action_result(ActionResult(param))

        block_hash = param[CARBONBLACK_JSON_HASH]

        data = {
            "md5hash": block_hash,
            "text": f"Blocked by Phantom for container {self.get_container_id()}",
            "last_ban_time": "0",
            "ban_count": "0",
            "last_ban_host": "0",
            "enabled": True,
        }

        comment = param.get(CARBONBLACK_JSON_COMMENT)

        if comment:
            data.update({"text": comment})

        # set the isolation status
        data["enabled"] = True

        # make a rest call to set the hash state
        ret_val, response = self._make_rest_call(
            "/v1/banning/blacklist", action_result, method="post", data=data, parse_response_json=False, additional_succ_codes={409: None}
        )

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            action_result.update_summary({"status": "success"})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_BLOCK if (not response or type(response) != str) else response)

    def _add_sensor_info_to_result(self, sensors, action_result):
        for sensor in sensors:
            action_result.add_data(sensor)
            if "network_adapters" not in sensor:
                continue

            adapters = sensor["network_adapters"].split("|")

            if not adapters:
                continue

            ips = []
            for adapter in adapters:
                ip = adapter.split(",")[0].strip()
                if not ip:
                    continue
                ips.append(ip)

            sensor[CARBONBLACK_JSON_IPS] = ",".join(ips)

    def _list_endpoints(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ret_val, sensors = self._make_rest_call("/v1/sensor", action_result, additional_succ_codes={204: []})

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.set_summary({CARBONBLACK_JSON_TOTAL_ENDPOINTS: len(sensors)})

        if not sensors:
            return action_result.set_status(phantom.APP_SUCCESS)

        self._add_sensor_info_to_result(sensors, action_result)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_watchlists(self, action_result, wl_id=None):
        endpoint = "/v1/watchlist"

        if wl_id:
            endpoint = f"{endpoint}/{wl_id}"

        ret_val, watchlists = self._make_rest_call(endpoint, action_result, additional_succ_codes={204: []})

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, watchlists)

    def _list_alerts(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ret_val, watchlists = self._get_watchlists(action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.set_summary({CARBONBLACK_JSON_TOTAL_WATCHLISTS: len(watchlists)})

        for watchlist in watchlists:
            try:
                watchlist["quoted_query"] = six.moves.urllib.parse.unquote(watchlist["search_query"][2:].replace("cb.urlver=1&", ""))
                watchlist["query_type"] = (
                    CARBONBLACK_QUERY_TYPE_BINARY if watchlist["index_type"] == "modules" else CARBONBLACK_QUERY_TYPE_PROCESS
                )
            except:
                pass
            action_result.add_data(watchlist)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _run_query(self, param):
        action_result = self.add_action_result(ActionResult(param))

        query_type = param[CARBONBLACK_JSON_QUERY_TYPE]

        if query_type not in VALID_QUERY_TYPE:
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_QUERY_TYPE.format(types=", ".join(VALID_QUERY_TYPE)))

        query = param[CARBONBLACK_JSON_QUERY]

        ret_val, start, rows = self._parse_range(param, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(CARBONBLACK_RUNNING_QUERY)

        ret_val, search_results = self._search(query_type, action_result, query, start=start, rows=rows)

        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_PROCESS_SEARCH)

        action_result.add_data(search_results)

        action_result.set_summary({CARBONBLACK_JSON_NUM_RESULTS: len(search_results.get("results", []))})

        return action_result.set_status(
            phantom.APP_SUCCESS,
            CARBONBLACK_DISPLAYING_RESULTS_TOTAL.format(
                displaying=len(search_results.get("results", [])), query_type=query_type, total=search_results.get("total_results", "Unknown")
            ),
        )

    def _update_alerts(self, param):
        action_result = self.add_action_result(ActionResult(param))

        update_data = {}
        total_results = 0

        query = param.get("query")
        if query:
            search_data = {"q": [query]}
            update_data["query"] = "{}{}".format("q=", six.moves.urllib.parse.quote(query))

            # run a pre-query to get the number of results for bulk update since it is not returned by bulk alert update API
            ret_val, result = self._make_rest_call("/v2/alert", action_result, method="post", data=search_data)
            if phantom.is_fail(ret_val):
                return action_result.get_status()
            total_results = result.get("total_results", 0)

        alert_ids = param.get("alert_ids")
        if alert_ids:
            alert_ids = alert_ids.split(",")
            update_data["alert_ids"] = alert_ids
            total_results = len(alert_ids)

        requested_status = param["requested_status"]

        if requested_status in VALID_ALERT_STATUS:
            update_data["requested_status"] = requested_status
        else:
            return action_result.set_status(
                phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_ALERT_STATUS.format(status=", ".join(VALID_ALERT_STATUS))
            )

        set_ignored = param.get("set_ignored")
        if set_ignored:
            update_data["set_ignored"] = set_ignored

        assigned_to = param.get("assigned_to")
        if assigned_to:
            update_data["assigned_to"] = assigned_to

        # query or alert_ids are required, but not both
        if (not query and not alert_ids) or (query and alert_ids):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_UPDATE_ALERTS_PARAM_IDS)

        ret_val, result = self._make_rest_call("/v1/alerts", action_result, method="post", data=update_data)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        action_result.update_summary({"result": result["result"], "total_records_updated": total_results})

        action_result.add_data(result)

        return action_result.set_status(phantom.APP_SUCCESS)

    def _create_alert(self, param):
        action_result = self.add_action_result(ActionResult(param))

        query_type = param[CARBONBLACK_JSON_ALERT_TYPE]

        if query_type not in VALID_QUERY_TYPE:
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_QUERY_TYPE.format(types=", ".join(VALID_QUERY_TYPE)))

        query = param[CARBONBLACK_JSON_QUERY]

        query = six.moves.urllib.parse.quote(query)

        if "cb.urlver=1&" not in query:
            query = f"cb.urlver=1&{query}"

        if "q=" not in query:
            query_parts = query.split("&")
            query_parts[1] = f"q={query_parts[1]}"
            query = "&".join(query_parts)

        name = param[CARBONBLACK_JSON_NAME]
        read_only = param.get(CARBONBLACK_JSON_READONLY, False)

        self.save_progress(CARBONBLACK_ADDING_WATCHLIST)

        # default to binary/modules
        index_type = "modules"
        if query_type == CARBONBLACK_QUERY_TYPE_PROCESS:
            index_type = "events"

        for kvpair in query.split("&"):
            # print kvpair
            if len(kvpair.split("=")) != 2:
                continue
            if kvpair.split("=")[0] != "q":
                continue

            # the query itself must be percent-encoded
            # verify there are only non-reserved characters present
            # no logic to detect unescaped '%' characters
            for c in kvpair.split("=")[1]:
                if c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~%":
                    return action_result.set_status(
                        phantom.APP_ERROR, f"Unescaped non-reserved character '{c}' found in query; use percent-encoding"
                    )

        request = {"index_type": index_type, "name": name, "search_query": query, "readonly": read_only}

        ret_val, watchlist = self._make_rest_call("/v1/watchlist", action_result, method="post", data=request)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        self.save_progress(CARBONBLACK_ADDED_WATCHLIST)

        self.save_progress(CARBONBLACK_FETCHING_WATCHLIST_INFO)

        if "id" not in watchlist:
            return action_result.set_status(phantom.APP_ERROR, "Watchlist ID not found in the recently added watchlist")

        ret_val, watchlist = self._get_watchlists(action_result, watchlist["id"])

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        try:
            watchlist["quoted_query"] = six.moves.urllib.parse.unquote(watchlist["search_query"][2:].replace("cb.urlver=1&", ""))
            watchlist["query_type"] = CARBONBLACK_QUERY_TYPE_BINARY if watchlist["index_type"] == "modules" else CARBONBLACK_QUERY_TYPE_PROCESS
        except:
            pass

        action_result.add_data(watchlist)

        action_result.set_summary({CARBONBLACK_JSON_ADDED_WL_ID: watchlist["id"]})

        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_range(self, param, action_result):
        range = param.get(CARBONBLACK_JSON_RANGE, "0-10")

        p = parse("{start}-{end}", range)

        # Check if the format of the range is correct
        if p is None:
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_RANGE), None, None)

        # get the values in int
        ret_val, start = self._validate_integer(action_result, p["start"], "range", True)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_RANGE), None, None

        ret_val, end = self._validate_integer(action_result, p["end"], "range", True)
        if phantom.is_fail(ret_val):
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_RANGE), None, None

        # Validate the range set
        if end < start:
            return (action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_RANGE), None, None)

        # get the rows
        rows = end - start

        # if the number of rows is zero, that means the user wants just one entry
        if rows == 0:
            rows = 1

        return (phantom.APP_SUCCESS, start, rows)

    def _search(self, search_type, action_result, query, start, rows):
        api_version = 1
        search_data = {
            "params": "server_added_timestamp desc",
            "start": start,
            "rows": rows,
            "facet": ["true", "true"],
            "cb.urlver": ["1"],
            "q": [query],
        }

        if search_type == "alert":
            api_version = 2
            del search_data["facet"]
            del search_data["cb.urlver"]

        # Search results are returned as lists
        ret_val, response = self._make_rest_call(
            f"/v{api_version}/{search_type}", action_result, method="post", data=search_data, additional_succ_codes={204: []}
        )

        if phantom.is_fail(ret_val):
            return (action_result.get_status(), None)

        return (phantom.APP_SUCCESS, response)

    def _hunt_file(self, param):
        query_type = param[CARBONBLACK_JSON_QUERY_TYPE]

        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, start, rows = self._parse_range(param, action_result)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if query_type not in VALID_QUERY_TYPE:
            return action_result.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_INVALID_QUERY_TYPE.format(types=", ".join(VALID_QUERY_TYPE)))

        data = action_result.add_data({query_type: None})

        self.save_progress(CARBONBLACK_DOING_SEARCH.format(query_type=query_type))

        # Binary search
        ret_val, results = self._search(query_type, action_result, f"md5:{param[CARBONBLACK_JSON_HASH]}", start=start, rows=rows)

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if phantom.is_success(ret_val) and results:
            data[query_type] = results

        summary = CARBONBLACK_DISPLAYING_RESULTS_TOTAL.format(
            displaying=len(results.get("results", [])), query_type=query_type, total=results.get("total_results", "Unknown")
        )

        action_result.set_summary({"device_count": results.get("total_results", "Unknown")})

        return action_result.set_status(phantom.APP_SUCCESS, summary)

    def _list_connections(self, param):
        """All of the parameters for this optional, but of course some need to present
        " Fundamentally, it should work like this:
        "
        " if carbonblack_id
        "     get connections for id
        " elif pid AND ip_hostname:
        "     get list of hosts
        "     for each host, get connections for pid
        " elif process_name AND ip_hostname:
        "     get list of hosts
        "     for each host, get connections for process_name
        " else
        "     invalid input
        "
        " The parameters for this function have become kind of convoluted at this point
        " That said, _get_connections_for_process is generic enough to work on any search criteria
        " If some parameters need to be added to this in the future, you'll need to figure out
        "  how to turn the criteria into parameters for a process search
        " Then, you'll need to decide if ip_hostname is required to be used with it
        """
        ret_val, pid = self._validate_integer(self, param.get(CARBONBLACK_JSON_PID), CARBONBLACK_JSON_PID, True)
        if phantom.is_fail(ret_val):
            action_result = self.add_action_result(ActionResult(param))
            return action_result.set_status(phantom.APP_ERROR, self.get_status_message())
        ip_hostname = param.get(phantom.APP_JSON_IP_HOSTNAME, "")
        process = param.get(CARBONBLACK_JSON_PROCESS_NAME, "")
        cb_id = param.get(CARBONBLACK_JSON_CB_ID, "")

        # We need to validate that the user gave proper input
        # Needs search criteria
        if not pid and not process and not cb_id:
            action_result = self.add_action_result(ActionResult(param))
            msg = f"Need to specify at least one of {CARBONBLACK_JSON_PROCESS_NAME}, {CARBONBLACK_JSON_PID}, or {CARBONBLACK_JSON_CB_ID}"
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Searching by carbonblack id is a bit different
        if cb_id:
            action_result = self.add_action_result(ActionResult(param))
            query_parameters = {"cb.q.process_id": cb_id}
            return self._get_connections_for_process(query_parameters, action_result)

        # Need a hostname to search by pid or process id
        if not ip_hostname:
            action_result = self.add_action_result(ActionResult(param))
            msg = f"Need to specify an IP or hostname to search by {CARBONBLACK_JSON_PROCESS_NAME} or {CARBONBLACK_JSON_PID}"
            return action_result.set_status(phantom.APP_ERROR, msg)

        # Get a list of systems matching ip/hostname
        sys_info_ar = ActionResult(param)

        ret_val = self._get_system_info_from_cb(ip_hostname, sys_info_ar)

        if phantom.is_fail(ret_val):
            self.add_action_result(sys_info_ar)
            return sys_info_ar.get_status()

        systems = sys_info_ar.get_data()

        if not systems:
            self.add_action_result(sys_info_ar)
            return sys_info_ar.set_status(phantom.APP_ERROR, CARBONBLACK_ERROR_NO_ENDPOINTS.format(ip_hostname))

        # Generate query parameters
        query_parameters = {}
        if pid:
            query_parameters["cb.q.process_pid"] = pid
            d = {"pid": pid}
        else:
            query_parameters["cb.q.process_name"] = process
            d = {"process_name": process}

        # Find process / pid on each system
        for system in systems:
            action_result = self.add_action_result(ActionResult(dict(d, **{phantom.APP_JSON_IP_HOSTNAME: system.get("computer_name")})))
            if system.get("status") != "Online":
                action_result.set_status(phantom.APP_ERROR, "Ignoring Offline Endpoint")
                continue
            query_parameters["cb.q.hostname"] = system.get("computer_name")
            self._get_connections_for_process(query_parameters, action_result)

        return phantom.APP_SUCCESS

    def _validate_version(self, action_result):
        # make a rest call to get the info
        ret_val, info = self._make_rest_call("/info", action_result)

        if phantom.is_fail(ret_val):
            action_result.append_to_message("Product version validation failed.")
            return action_result.get_status()

        # get the version of the device
        device_version = info.get("version")
        if not device_version:
            return action_result.set_status(phantom.APP_ERROR, "Unable to get version from the device")

        self.save_progress(f"Got device version: {device_version}")

        # get the configured version regex
        version_regex = self.get_product_version_regex()
        if not version_regex:
            # assume that it matches
            return phantom.APP_SUCCESS

        match = re.match(version_regex, device_version)

        if not match:
            self.debug_print(f"This version of CarbonBlack is not officially supported. Supported versions: '{version_regex}'")
            # self.save_progress(message)

        self.save_progress("Version validation done")

        return phantom.APP_SUCCESS

    def _reset_session(self, param):
        action_result = self.add_action_result(ActionResult(param))

        ret_val, session_id = self._validate_integer(action_result, param.get(CARBONBLACK_JSON_SESSION_ID), CARBONBLACK_JSON_SESSION_ID, True)
        if phantom.is_fail(ret_val):
            return action_result.get_status()

        url = f"/v1/cblr/session/{session_id}/keepalive"
        error_msg = CARBONBLACK_ERROR_RESET_SESSION.format(session_id=session_id)

        # make a rest call to get the info
        ret_val, response = self._make_rest_call(url, action_result, additional_succ_codes={404: error_msg})

        if phantom.is_fail(ret_val):
            return action_result.get_status()

        if response == error_msg:
            return action_result.set_status(phantom.APP_ERROR, response)

        try:
            action_result.update_summary({"status": response["status"]})
        except:
            pass

        return action_result.set_status(phantom.APP_SUCCESS, CARBONBLACK_SUCC_RESET_SESSION.format(session_id=session_id))

    def _paginator(self, endpoint, action_result, max_containers=None):
        result_list = list()

        # Make an API call first time for retrieving total records
        ret_val, response = self._make_rest_call(endpoint, action_result)

        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR

        total_results = response.get("total_results")
        result = response["results"]

        # start indicates records which helps to traverse the records
        start = len(result)
        result_list.extend(result)
        while start < total_results:
            endpoint_temp = f"{endpoint}&start={start}"
            ret_val, response = self._make_rest_call(endpoint_temp, action_result)
            if phantom.is_fail(ret_val):
                self.debug_print(action_result.get_message())
                self.set_status(phantom.APP_ERROR, action_result.get_message())
                return phantom.APP_ERROR

            result = response["results"]
            result_list.extend(result)

            # Will break the loop when total_records < max_containers in case of manual poll.
            if len(result) == 0:
                break

            if max_containers:
                if int(max_containers) <= len(result_list):
                    return result_list[:max_containers]

            start = start + len(result)

        return result_list

    def _on_poll(self, param):
        DT_STR_FORMAT = "%Y-%m-%dT%H:%M:%S"

        # Add action result
        action_result = self.add_action_result(phantom.ActionResult(param))
        max_containers = None

        if self.is_poll_now():
            # Manual poll
            max_containers = int(param.get(phantom.APP_JSON_CONTAINER_COUNT))
            endpoint = f"/v1/alert?cb.q.created_time=%5B{datetime.datetime(1970, 1, 1).strftime(DT_STR_FORMAT)}%20TO%20*%5D&cb.fq.status=Unresolved&sort=alert_severity%20desc"
            self.save_progress(endpoint)
        else:
            # Scheduled poll
            if self._state.get("first_run", True):
                self._state["first_run"] = False
                self._state.update({"last_ingested_time": datetime.datetime(1970, 1, 1).strftime(DT_STR_FORMAT)})

            endpoint = "/v1/alert?cb.q.created_time=%5B{}%20TO%20*%5D&cb.fq.status=Unresolved&sort=alert_severity%20desc".format(
                self._state["last_ingested_time"]
            )

        result_list = self._paginator(endpoint, action_result, max_containers)

        if not self.is_poll_now():
            # save last_ingested_time into the state file
            self._state["last_ingested_time"] = datetime.datetime.now().strftime(DT_STR_FORMAT)
            self.save_state(self._state)

        for result in result_list:
            cef = {}
            cont = {}
            cont["name"] = "Unresolved CB_Response Alert: " + result["watchlist_name"]
            cont["description"] = "Unresolved CB_Response Alerts"
            cont["source_data_identifier"] = result["unique_id"]

            for key, value in result.items():
                cef[key] = value
                # Create List to contain artifacts
                artList = []
                # Create the artifact
                art = {
                    "label": "alert",
                    "cef": cef,
                }
                # Append Artifact to List
                artList.append(art)
                cont["data"] = result
                # Create "artifacts" field in Container
                cont["artifacts"] = artList

            status, msg, container_id_ = self.save_container(cont)
            if status == phantom.APP_ERROR:
                self.debug_print(f"Failed to store: {msg}")
                self.debug_print(f"stat/msg {status}/{msg}")
                action_result.set_status(phantom.APP_ERROR, f"Container creation failed: {msg}")
                return status

        return action_result.set_status(phantom.APP_SUCCESS)

    def _test_connectivity(self, param):
        # Progress
        self.save_progress(CARBONBLACK_USING_BASE_URL.format(base_url=self._base_url))

        url = self._base_url
        host = url[url.find("//") + 2 :]

        # Connectivity
        self.save_progress(phantom.APP_PROG_CONNECTING_TO_ELLIPSES, host)

        action_result = self.add_action_result(ActionResult(dict(param)))

        # validate the version, this internally makes all the rest calls to validate the config also
        ret_val = self._validate_version(action_result)

        if phantom.is_fail(ret_val):
            action_result.append_to_message(CARBONBLACK_ERROR_CONNECTIVITY_TEST)
            return action_result.get_status()

        self.save_progress(CARBONBLACK_SUCC_CONNECTIVITY_TEST)
        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):
        # Get the action that we are supposed to execute for this app run
        self.debug_print("action_id", self.get_action_identifier())

        action_mapping = {
            self.ACTION_ID_TEST_CONNECTIVITY: self._test_connectivity,
            self.ACTION_ID_HUNT_FILE: self._hunt_file,
            self.ACTION_ID_LIST_ALERTS: self._list_alerts,
            self.ACTION_ID_LIST_ENDPOINTS: self._list_endpoints,
            self.ACTION_ID_CREATE_ALERT: self._create_alert,
            self.ACTION_ID_UPDATE_ALERTS: self._update_alerts,
            self.ACTION_ID_RUN_QUERY: self._run_query,
            self.ACTION_ID_QUARANTINE_DEVICE: self._quarantine_device,
            self.ACTION_ID_UNQUARANTINE_DEVICE: self._unquarantine_device,
            self.ACTION_ID_SYNC_EVENTS: self._sync_events,
            self.ACTION_ID_GET_SYSTEM_INFO: self._get_system_info,
            self.ACTION_ID_LIST_PROCESSES: self._list_processes,
            self.ACTION_ID_TERMINATE_PROCESS: self._terminate_process,
            self.ACTION_ID_GET_FILE: self._get_file,
            self.ACTION_ID_GET_FILE_INFO: self._get_file_info,
            self.ACTION_ID_BLOCK_HASH: self._block_hash,
            self.ACTION_ID_UNBLOCK_HASH: self._unblock_hash,
            self.ACTION_ID_LIST_CONNECTIONS: self._list_connections,
            self.ACTION_ID_GET_LICENSE: self._get_license,
            self.ACTION_ID_ON_POLL: self._on_poll,
            self.ACTION_ID_PUT_FILE: self._put_file,
            self.ACTION_ID_RUN_COMMAND: self._run_command,
            self.ACTION_ID_EXECUTE_PROGRAM: self._execute_program,
            self.ACTION_ID_RESET_SESSION: self._reset_session,
            self.ACTION_ID_MEMORY_DUMP: self._memory_dump,
        }

        action = self.get_action_identifier()
        action_execution_status = phantom.APP_SUCCESS

        if action in action_mapping.keys():
            action_function = action_mapping[action]
            action_execution_status = action_function(param)

        return action_execution_status


if __name__ == "__main__":
    import argparse

    import pudb

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument("input_test_json", help="Input Test JSON file")
    argparser.add_argument("-u", "--username", help="username", required=False)
    argparser.add_argument("-p", "--password", help="password", required=False)
    argparser.add_argument("-v", "--verify", action="store_true", help="verify", required=False, default=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password
    verify = args.verify

    if username is not None and password is None:
        # User specified a username but not a password, so ask
        import getpass

        password = getpass.getpass("Password: ")

    if username and password:
        try:
            print("Accessing the Login page")
            r = requests.get(BaseConnector._get_phantom_base_url() + "login", verify=verify)
            csrftoken = r.cookies["csrftoken"]

            data = dict()
            data["username"] = username
            data["password"] = password
            data["csrfmiddlewaretoken"] = csrftoken

            headers = dict()
            headers["Cookie"] = "csrftoken=" + csrftoken
            headers["Referer"] = BaseConnector._get_phantom_base_url() + "login"

            print("Logging into Platform to get the session id")
            r2 = requests.post(BaseConnector._get_phantom_base_url() + "login", verify=verify, data=data, headers=headers)
            session_id = r2.cookies["sessionid"]
        except Exception as e:
            print("Unable to get session id from the platfrom. Error: " + str(e))
            sys.exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = CarbonblackConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json["user_session_token"] = session_id
            connector._set_csrf_info(csrftoken, headers["Referer"])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    sys.exit(0)
