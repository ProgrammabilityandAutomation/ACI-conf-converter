# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
import json
import traceback
from django.http import HttpResponse
from rest_framework.renderers import JSONRenderer
from controllers import apic_controller


# ====================>>>>>>>> Utils <<<<<<<<====================
class JSONResponse(HttpResponse):
    """
    An HttpResponse that renders its content into JSON.
    """

    def __init__(self, data, **kwargs):
        content = JSONRenderer().render(data)
        kwargs['content_type'] = 'application/json'
        super(JSONResponse, self).__init__(content, **kwargs)


# ====================>>>>>>>> Templates <<<<<<<<====================
def index(request):
    return render(request, 'web_app/index.html')


def home(request):
    return render(request, 'web_app/home.html')


def configure(request):
    return render(request, 'web_app/configure_aci.html')


def results(request):
    return render(request, 'web_app/configuration_results.html')


# ====================>>>>>>>> APIs <<<<<<<<====================
@csrf_exempt
def api_ntp(request):
    """
    POST:
        Add NTP Server
    :param request:
    :return:
    """
    if request.method == 'POST':
        try:
            # Parse the json
            payload = json.loads(request.body)
            auth_token = apic_controller.get_token(url=payload['apic']['url'],
                                                   username=payload['apic']['username'],
                                                   password=payload['apic']['password'])

            apic_controller.add_default_group_policy(url=payload['apic']['url'],
                                                      auth_token=auth_token)

            apic_controller.add_ntp_pool(url=payload['apic']['url'],
                                         auth_token=auth_token,
                                         ntp_ip=payload['apic']['ntp']['ip'])

            apic_controller.add_ntp_group_policy(url=payload['apic']['url'],
                                                 auth_token=auth_token)

            apic_controller.add_default_pod_profile(url=payload['apic']['url'],
                                                    auth_token=auth_token)

            return JSONResponse('ok')
        except Exception as e:
            print traceback.print_exc()
            # return the error to web client
            return JSONResponse({'error': e.__class__.__name__, 'message': str(e)}, status=500)
    else:
        return JSONResponse("Bad request. " + request.method + " is not supported", status=400)


@csrf_exempt
def api_dns(request):
    """
    POST:
        Add DNS Server
    :param request:
    :return:
    """
    if request.method == 'POST':
        try:
            # Parse the json
            payload = json.loads(request.body)
            auth_token = apic_controller.get_token(url=payload['apic']['url'],
                                                   username=payload['apic']['username'],
                                                   password=payload['apic']['password'])

            apic_controller.add_dns(url=payload['apic']['url'],
                                    auth_token=auth_token,
                                    dns_ip=payload['apic']['dns']['ip'])

            return JSONResponse('ok')
        except Exception as e:
            print traceback.print_exc()
            # return the error to web client
            return JSONResponse({'error': e.__class__.__name__, 'message': str(e)}, status=500)
    else:
        return JSONResponse("Bad request. " + request.method + " is not supported", status=400)


@csrf_exempt
def api_tacacs(request):
    """
    POST:
        Add TACACS+ Server
    :param request:
    :return:
    """
    if request.method == 'POST':
        try:
            # Parse the json
            payload = json.loads(request.body)

            auth_token = apic_controller.get_token(url=payload['apic']['url'],
                                                   username=payload['apic']['username'],
                                                   password=payload['apic']['password'])

            if 'password' in payload['apic']['tacacs'].keys():
                apic_controller.add_tacacs_provider(url=payload['apic']['url'],
                                                    auth_token=auth_token,
                                                    tacacs_ip=payload['apic']['tacacs']['ip'],
                                                    tacacs_password=payload['apic']['tacacs']['password'])

            else:
                apic_controller.add_tacacs_provider(url=payload['apic']['url'],
                                                    auth_token=auth_token,
                                                    tacacs_ip=payload['apic']['tacacs']['ip'],
                                                    tacacs_password='')

            apic_controller.add_tacacs_group(url=payload['apic']['url'],
                                             auth_token=auth_token,
                                             tacacs_ip=payload['apic']['tacacs']['ip'])

            apic_controller.add_tacacs_login_domain(url=payload['apic']['url'],
                                                    auth_token=auth_token)

            return JSONResponse('ok')
        except Exception as e:
            print traceback.print_exc()
            # return the error to web client
            return JSONResponse({'error': e.__class__.__name__, 'message': str(e)}, status=500)
    else:
        return JSONResponse("Bad request. " + request.method + " is not supported", status=400)


@csrf_exempt
def api_syslog(request):
    """
    POST:
        Add SysLog Server
    :param request:
    :return:
    """
    if request.method == 'POST':
        try:
            # Parse the json
            payload = json.loads(request.body)
            auth_token = apic_controller.get_token(url=payload['apic']['url'],
                                                   username=payload['apic']['username'],
                                                   password=payload['apic']['password'])

            apic_controller.add_syslog_group(url=payload['apic']['url'],
                                             auth_token=auth_token,
                                             syslog_ip=payload['apic']['syslog']['ip'])

            apic_controller.add_syslog_access_policy(url=payload['apic']['url'],
                                                     auth_token=auth_token)

            apic_controller.add_syslog_fabric_policy(url=payload['apic']['url'],
                                                     auth_token=auth_token)
            return JSONResponse('ok')
        except Exception as e:
            print traceback.print_exc()
            # return the error to web client
            return JSONResponse({'error': e.__class__.__name__, 'message': str(e)}, status=500)
    else:
        return JSONResponse("Bad request. " + request.method + " is not supported", status=400)


@csrf_exempt
def api_snmp(request):
    """
    POST:
        Add SNMP Server
    :param request:
    :return:
    """
    if request.method == 'POST':
        try:
            # Parse the json
            payload = json.loads(request.body)
            auth_token = apic_controller.get_token(url=payload['apic']['url'],
                                                   username=payload['apic']['username'],
                                                   password=payload['apic']['password'])
            security_level = ""

            if 'snmp' in payload['apic']:

                if 'security_level' in payload['apic']['snmp'].keys():
                    security_level = payload['apic']['snmp']['security_level']

                # Add SNMP group
                apic_controller.add_snmp_group(url=payload['apic']['url'],
                                               auth_token=auth_token,
                                               snmp_ip=payload['apic']['snmp']['ip'],
                                               snmp_port=payload['apic']['snmp']['port'],
                                               snmp_community_name=payload['apic']['snmp']['community_name'],
                                               snmp_version=payload['apic']['snmp']['version'],
                                               snmp_security_level=security_level)

                # Add SNMP access policy
                apic_controller.add_snmp_access_policy(url=payload['apic']['url'],
                                                       auth_token=auth_token)

                # Add SNMP pod policy
                apic_controller.add_snmp_fabric_policy(url=payload['apic']['url'],
                                                       auth_token=auth_token)

                # Enable default SNMP pod policy
                apic_controller.enable_snmp_default_pod_policy(url=payload['apic']['url'],
                                                               auth_token=auth_token)

                # Add users
                for user in payload['apic']['snmp']['users']:
                    priv_key = ''
                    priv_type = 'none'
                    if 'priv_key' in user.keys():
                        priv_key = user['priv_key']
                    if 'priv_type' in user.keys():
                        priv_type = user['priv_type']
                    if 'auth_key' in user.keys():
                        apic_controller.add_snmp_v3_user(url=payload['apic']['url'],
                                                         auth_token=auth_token,
                                                         username=user['username'],
                                                         priv_type=priv_type,
                                                         priv_key=priv_key,
                                                         auth_key=user['auth_key'],
                                                         auth_type=user['auth_type'])

                # Create SNMP community policy

                apic_controller.add_snmp_community_pod_policy(url=payload['apic']['url'],
                                                              auth_token=auth_token,
                                                              community_name=payload['apic']['snmp']['community_name'])

            return JSONResponse('ok')
        except Exception as e:
            print traceback.print_exc()
            # return the error to web client
            return JSONResponse({'error': e.__class__.__name__, 'message': str(e)}, status=500)
    else:
        return JSONResponse("Bad request. " + request.method + " is not supported", status=400)
