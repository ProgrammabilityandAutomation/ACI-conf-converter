"""
Manages calls to the ACI Controller (APIC)

Examples:


Syslog

method: POST
url: https://apic-lab.dcloud.cisco.com/api/node/mo/uni/fabric/slgroup-groupte-test.json
payload{"syslogGroup":{"attributes":{"dn":"uni/fabric/slgroup-groupte-test","name":"groupte-test","rn":"slgroup-groupte-test","status":"created"},"children":[{"syslogConsole":{"attributes":{"dn":"uni/fabric/slgroup-groupte-test/console","rn":"console","status":"created"},"children":[]}},{"syslogFile":{"attributes":{"dn":"uni/fabric/slgroup-groupte-test/file","rn":"file","status":"created"},"children":[]}},{"syslogProf":{"attributes":{"dn":"uni/fabric/slgroup-groupte-test/prof","rn":"prof","status":"created"},"children":[]}},{"syslogRemoteDest":{"attributes":{"dn":"uni/fabric/slgroup-groupte-test/rdst-1.1.1.1","host":"1.1.1.1","name":"test","rn":"rdst-1.1.1.1","status":"created"},"children":[{"fileRsARemoteHostToEpg":{"attributes":{"tDn":"uni/tn-mgmt/mgmtp-default/oob-default","status":"created"},"children":[]}}]}}]}}
response: {"totalCount":"0","imdata":[]}

SNMP

method: POST
url: https://apic-lab.dcloud.cisco.com/api/node/mo/uni/fabric/snmpgroup-snmp-test.json
payload{"snmpGroup":{"attributes":{"dn":"uni/fabric/snmpgroup-snmp-test","name":"snmp-test","rn":"snmpgroup-snmp-test","status":"created"},"children":[{"snmpTrapDest":{"attributes":{"dn":"uni/fabric/snmpgroup-snmp-test/trapdest-2.2.2.2-port-162","host":"2.2.2.2","secName":"public","rn":"trapdest-2.2.2.2-port-162","status":"created"},"children":[{"fileRsARemoteHostToEpg":{"attributes":{"tDn":"uni/tn-mgmt/mgmtp-default/oob-default","status":"created"},"children":[]}}]}}]}}
response: {"totalCount":"0","imdata":[]}

NTP

method: POST
url: https://apic-lab.dcloud.cisco.com/api/node/mo/uni/fabric/time-default/ntpprov-3.3.3.3.json
payload{"datetimeNtpProv":{"attributes":{"dn":"uni/fabric/time-default/ntpprov-3.3.3.3","name":"3.3.3.3","preferred":"true","rn":"ntpprov-3.3.3.3","status":"created"},"children":[{"datetimeRsNtpProvToEpg":{"attributes":{"tDn":"uni/tn-mgmt/mgmtp-default/oob-default","status":"created"},"children":[]}}]}}
response: {"totalCount":"0","imdata":[]}

DNS
method: POST
url: https://apic-lab.dcloud.cisco.com/api/node/mo/uni/fabric/dnsp-default/prov-[4.4.4.4].json
payload{"dnsProv":{"attributes":{"dn":"uni/fabric/dnsp-default/prov-[4.4.4.4]","addr":"4.4.4.4","status":"created","preferred":"true","rn":"prov-[4.4.4.4]"},"children":[]}}
response: {"totalCount":"0","imdata":[]}

TACACS

method: POST
url: https://apic-lab.dcloud.cisco.com/api/node/mo/uni/userext/tacacsext/tacacsplusprovider-5.5.5.5.json
payload{"aaaTacacsPlusProvider":{"attributes":{"dn":"uni/userext/tacacsext/tacacsplusprovider-5.5.5.5","name":"5.5.5.5","key":"cisco123","rn":"tacacsplusprovider-5.5.5.5","status":"created"},"children":[{"aaaRsSecProvToEpg":{"attributes":{"tDn":"uni/tn-mgmt/mgmtp-default/oob-default","status":"created"},"children":[]}}]}}
response: {"totalCount":"0","imdata":[]}
"""

from jinja2 import Environment
from jinja2 import FileSystemLoader
import os
import requests
import json

DIR_PATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
JSON_TEMPLATES = Environment(loader=FileSystemLoader(DIR_PATH + '/json_templates'))


def get_token(url, username, password):
    """
    Returns authentication token
    :param url:
    :param username:
    :param password:
    :return:
    """
    template = JSON_TEMPLATES.get_template('login.j2.json')
    payload = template.render(username=username, password=password)
    response = requests.post(url + '/api/aaaLogin.json', data=payload, verify=False)
    if 199 < response.status_code < 300:
        auth = json.loads(response.text)
        login_attributes = auth['imdata'][0]['aaaLogin']['attributes']
        return login_attributes['token']
    else:
        raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_dns(url, auth_token, dns_ip):
    """
    Creates a DNS Server in APIC
    :param url:
    :param auth_token:
    :param dns_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_dns.j2.json')
    payload = template.render(dns_ip=dns_ip)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/dnsp-default/prov-[' + dns_ip + '].json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])

    template = JSON_TEMPLATES.get_template('add_dns_mgmt_epg.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/dnsp-default/rsProfileToEpg.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_ntp_pool(url, auth_token, ntp_ip):
    """
    Creates a NTP pool in APIC
    :param url:
    :param auth_token:
    :param ntp_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_ntp_pool.j2.json')
    payload = template.render(ntp_ip=ntp_ip)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/time-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_ntp_group_policy(url, auth_token):
    """
    Add conf converter NTP pool to default group policy
    :param url:
    :param auth_token:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_ntp_to_group_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/funcprof/podpgrp-default/rsTimePol.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_default_pod_profile(url, auth_token):
    """
    Add default policy group to pod profile
    :param url:
    :param auth_token:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_default_pod_profile.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/podprof-default/pods-default-typ-ALL/rspodPGrp.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_snmp_group(url, auth_token, snmp_ip, snmp_port, snmp_community_name, snmp_security_level="", snmp_version='2c'):
    """
    Creates a SNMP Server in APIC
    :param url:
    :param auth_token:
    :param snmp_ip:
    :return:
    """
    if snmp_version == '2c':
        template = JSON_TEMPLATES.get_template('add_snmp_group.j2.json')
    else:
        template = JSON_TEMPLATES.get_template('add_snmp_group_v3.j2.json')
    payload = template.render(snmp_ip=snmp_ip,
                              snmp_port=snmp_port,
                              snmp_community_name=snmp_community_name,
                              snmp_security_level=snmp_security_level)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/snmpgroup-snmp-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_snmp_access_policy(url, auth_token):
    """
    Creates a SNMP access policy in APIC
    :param url:
    :param auth_token:
    :param snmp_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_snmp_access_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/infra/moninfra-default/snmpsrc-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_snmp_fabric_policy(url, auth_token):
    """
    Creates a SNMP access policy in APIC
    :param url:
    :param auth_token:
    :param snmp_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_snmp_fabric_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/monfab-default/snmpsrc-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_snmp_v3_user(url, auth_token, **kwargs):
    """
    Creates a SNMP v3 user in default snmp pod policy
    :param url:
    :param auth_token:
    :param snmp_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_snmp_v3_user.j2.json')
    payload = template.render(kwargs)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/snmppol-default/user-' + kwargs['username'] + '.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def enable_snmp_default_pod_policy(url, auth_token):
    """
    Creates a SNMP v3 user in default snmp pod policy
    :param url:
    :param auth_token:
    :return:
    """
    template = JSON_TEMPLATES.get_template('enable_snmp_default_pod_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/snmppol-default.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_snmp_community_pod_policy(url, auth_token, **kwargs):
    """
    Creates a community in the default snmp pod policy
    :param url:
    :param auth_token:

    :return:
    """
    template = JSON_TEMPLATES.get_template('add_snmp_community_pod_policy.j2.json')
    payload = template.render(kwargs)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(
        url + '/api/node/mo/uni/fabric/snmppol-default/community-' + kwargs['community_name'] + '.json',
        cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_syslog_group(url, auth_token, syslog_ip):
    """
    Creates a SysLog Server in APIC
    :param url:
    :param auth_token:
    :param syslog_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_syslog_group.j2.json')
    payload = template.render(syslog_ip=syslog_ip)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/slgroup-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_syslog_access_policy(url, auth_token):
    """
        Creates a SysLog access policy in APIC
        :param url:
        :param auth_token:
        :param syslog_ip:
        :return:
        """

    template = JSON_TEMPLATES.get_template('add_syslog_access_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/infra/moninfra-default/slsrc-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_syslog_fabric_policy(url, auth_token):
    """
        Creates a SysLog fabric policy in APIC
        :param url:
        :param auth_token:
        :param syslog_ip:
        :return:
        """

    template = JSON_TEMPLATES.get_template('add_syslog_fabric_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/monfab-default/slsrc-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_tacacs_provider(url, auth_token, tacacs_ip, tacacs_password):
    """
    Creates a Tacacs Server in APIC
    :param url:
    :param auth_token:
    :param tacacs_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_tacacs_provider.j2.json')
    payload = template.render(tacacs_ip=tacacs_ip,
                              tacacs_password=tacacs_password)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/userext/tacacsext/tacacsplusprovider-' + tacacs_ip + '.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_tacacs_group(url, auth_token, tacacs_ip):
    """
    Creates a Tacacs group in APIC
    :param url:
    :param auth_token:
    :param tacacs_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_tacacs_provider_group.j2.json')
    payload = template.render(tacacs_ip=tacacs_ip)
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/userext/tacacsext/tacacsplusprovidergroup-conf-converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_tacacs_login_domain(url, auth_token):
    """
    Creates a Tacacs login domain in APIC
    :param url:
    :param auth_token:
    :param tacacs_ip:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_login_domain_tacacs.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/userext/logindomain-conf_converter.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])


def add_default_group_policy(url, auth_token):
    """
    Creates a pod group policy called default
    :param url:
    :param auth_token:
    :return:
    """
    template = JSON_TEMPLATES.get_template('add_default_group_policy.j2.json')
    payload = template.render()
    cookies = {'APIC-Cookie': auth_token}
    response = requests.post(url + '/api/node/mo/uni/fabric/funcprof/podpgrp-default.json',
                             cookies=cookies, data=payload, verify=False)

    if 199 < response.status_code > 299:
        # Do not raise error if object is already there
        if " already exists" not in json.loads(response.text)['imdata'][0]['error']['attributes']['text']:
            raise Exception(json.loads(response.text)['imdata'][0]['error']['attributes']['text'])
