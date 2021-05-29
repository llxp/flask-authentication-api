from flask import Blueprint, request
from flask_cors import cross_origin
import json
import os
import ldap
import re
import traceback
from typing import Dict, List
from binascii import b2a_hex
from dataclasses import dataclass, field
from dataclasses_json import dataclass_json


app = Blueprint(
    'api',
    __name__)

ldap_host = os.getenv('LDAP_HOST', '192.168.6.1')
users_cn = os.getenv('USERS_CN', 'CN=Users,DC=ad,DC=lan')


@app.route('/login', methods=['POST'])
@cross_origin()
def login():
    json_body = request.json
    if json_body:
        if all(k in json_body for k in ('username', 'password')):
            username: str = json_body['username']
            password: str = json_body['password']
            if not username or not password:
                return json.dumps({'status': 'credentials missing'}), 400
            emailaddress_regex = r'[^@]+@[^@]+\.[^@]+'
            if not re.match(emailaddress_regex, username):
                return json.dumps(
                    {'status': 'username has to be an email address'}), 400
            conn = ldap.initialize('ldap://' + ldap_host)
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            try:
                conn.simple_bind_s(username, password)
                return json.dumps({'status': 'ok'}), 200
            except ldap.INVALID_CREDENTIALS:
                return json.dumps({'status': 'invalid credentials'}), 403
            except ldap.LDAPError:
                return json.dumps({'status': 'ldap error'}), 500
            finally:
                conn.unbind_s()
            return json.dumps({'status': 'error'}), 403
        return json.dumps({
            'status':
                'one of the following keys are missing: '
                'username, password'
            }), 400
    return json.dumps({'status': 'json body is missing'}), 400


def convert_object(obj: Dict):
    new_obj: Dict = dict()
    for key in obj:
        if isinstance(obj[key], bytes):
            try:
                new_obj[key] = \
                    obj[key].decode('utf-8')
            except UnicodeDecodeError:
                new_obj[key] = ''
                for char in obj[key]:
                    new_obj[key] += str(char)
        if isinstance(obj[key], list):
            new_obj[key] = convert_list(obj[key])
    return new_obj


def convert_list(input_list: List):
    first_result_list_converted = []
    for entry in input_list:
        if isinstance(entry, bytes):
            try:
                first_result_list_converted.append(
                    entry.decode('utf-8'))
            except UnicodeDecodeError:
                first_result_list_converted. \
                    append(entry.hex())
        if isinstance(entry, dict):
            first_result_list_converted.append(
                convert_object(entry))
    return first_result_list_converted


@dataclass_json
@dataclass(frozen=True)
class UserInformation():
    user_uid: str = ''
    username: str = ''
    groups: List[str] = field(default_factory=list)


def to_user_information(ldap_result: tuple):
    if len(ldap_result) > 0:
        ldap_data = ldap_result[0]
        if ldap_data:
            if (
                'objectSid' in ldap_data and
                'distinguishedName' in ldap_data
            ):
                if 'memberOf' in ldap_data:
                    return UserInformation(user_uid=ldap_data['objectSid'][0], username=ldap_data['distinguishedName'][0], groups=ldap_data['memberOf']).to_json()
                return UserInformation(user_uid=ldap_data['objectSid'][0], username=ldap_data['distinguishedName'][0], groups=[])
    return None


@app.route('/get_user_groups', methods=['POST'])
@cross_origin()
def get_user_groups():
    json_body = request.json
    if json_body:
        if all(k in json_body for k in ('username', 'password')):
            username: str = json_body['username']
            password: str = json_body['password']
            if not username or not password:
                return json.dumps({'status': 'credentials missing'}), 400
            emailaddress_regex = r'[^@]+@[^@]+\.[^@]+'
            if not re.match(emailaddress_regex, username):
                return json.dumps(
                    {'status': 'username has to be an email address'}), 400
            conn = ldap.initialize('ldap://' + ldap_host)
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            try:
                conn.simple_bind_s(username, password)
                ldap_result = conn.search_ext_s(
                    users_cn,
                    ldap.SCOPE_SUBTREE,
                    '(&(objectClass=*)'
                    '(samaccountname=' + username.split('@')[0] + '))',
                    None
                )
                if type(ldap_result) == list and len(ldap_result) >= 1:
                    first_result = ldap_result[0]
                    if type(first_result) == tuple:
                        first_result_list = list(first_result)

                        first_result_list_converted = \
                            convert_list(first_result_list)
                        return to_user_information(first_result_list_converted), 200
                        # return json.dumps(first_result_list_converted), 200
                return json.dumps(
                    {'status': 'error parsing the ldap result'}), 500
            except ldap.INVALID_CREDENTIALS:
                return json.dumps({'status': 'invalid credentials'}), 403
            except ldap.LDAPError:
                return json.dumps({'status': 'ldap error'}), 500
            finally:
                conn.unbind_s()
            return json.dumps({'status': 'error'}), 403
        return json.dumps({
            'status':
                'one of the following keys are missing: '
                'username, password'
            }), 400
    return json.dumps({'status': 'json body is missing'}), 400


def sid_to_str(sid):
    try:
        # Python 3
        if str is not bytes:
            # revision
            revision = int(sid[0])
            # count of sub authorities
            sub_authorities = int(sid[1])
            # big endian
            identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
            # If true then it is represented in hex
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)

            # loop over the count of small endians
            sub_authority = '-' + '-'.join(
                [
                    str(
                        int.from_bytes(
                            sid[8 + (i * 4): 12 + (i * 4)],
                            byteorder='little'
                        )
                    )
                    for i in range(sub_authorities)
                ]
            )
        # Python 2
        else:
            revision = int(b2a_hex(sid[0]))
            sub_authorities = int(b2a_hex(sid[1]))
            identifier_authority = int(b2a_hex(sid[2:8]), 16)
            if identifier_authority >= 2 ** 32:
                identifier_authority = hex(identifier_authority)

            sub_authority = '-' + '-'.join(
                [
                    str(
                        int(b2a_hex(sid[11 + (i * 4): 7 + (i * 4): -1]), 16)
                    )
                    for i in range(sub_authorities)
                ]
            )
        objectSid = 'S-' + str(revision) + '-' + \
            str(identifier_authority) + sub_authority

        return objectSid
    except Exception:
        pass

    return sid


@app.route('/translate_users', methods=['POST'])
@cross_origin()
def translate_users():
    json_body = request.json
    if json_body:
        if all(k in json_body for k in ('username', 'password', 'object_sids')):
            username: str = json_body['username']
            password: str = json_body['password']
            objectSids: str = json_body['object_sids']
            if not username or not password:
                return json.dumps({'status': 'credentials missing'}), 400
            emailaddress_regex = r'[^@]+@[^@]+\.[^@]+'
            if not re.match(emailaddress_regex, username):
                return json.dumps(
                    {'status': 'username has to be an email address'}), 400
            if type(objectSids) == list:
                try:
                    conn = ldap.initialize('ldap://' + ldap_host)
                    conn.protocol_version = 3
                    conn.set_option(ldap.OPT_REFERRALS, 0)
                    conn.simple_bind_s(username, password)
                    print(objectSids)
                    filter: str = \
                        '(&(objectClass=*)(|' + \
                        ''.join([
                            '(objectSid=' +
                            sid_to_str(bytearray.fromhex(objectSid)) + ')'
                            for objectSid in objectSids
                        ]) + '))'
                    print(filter)
                    ldap_result = conn.search_ext_s(
                        users_cn,
                        ldap.SCOPE_SUBTREE,
                        filter,
                        None
                    )
                    print(ldap_result)
                    if type(ldap_result) == list and len(ldap_result) >= 1:
                        result_list_converted = []
                        for current_result in ldap_result:
                            if type(current_result) == tuple:
                                current_result_list = list(current_result)

                                current_result_list_converted = \
                                    convert_list(current_result_list)
                                result_list_converted \
                                    .append(current_result_list_converted[0])
                        return json.dumps(result_list_converted), 200
                    return json.dumps({'status': 'not found'}), 404
                except ldap.INVALID_CREDENTIALS:
                    return json.dumps({'status': 'invalid credentials'}), 403
                except ldap.LDAPError as e:
                    traceback.print_exc()
                    return json.dumps({'status': 'ldap error'}), 500
                except Exception as e:
                    traceback.print_exc()
                finally:
                    conn.unbind_s()
                return json.dumps({'status': 'error'}), 403
            return json.dumps(
                {'status': 'object_sids needs to be a list'}), 400
        return json.dumps({
            'status':
                'one of the following keys are missing: '
                'username, password, object_sids'
            }), 400
    return json.dumps({'status': 'json body is missing'}), 400
