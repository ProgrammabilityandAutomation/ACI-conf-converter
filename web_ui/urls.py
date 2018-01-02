"""
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""
"""
URL mapping of the application
"""

from django.conf.urls import url

from . import views

urlpatterns = [

    # ====================>>>>>>>> Templates <<<<<<<<====================
    url(r'^$', views.index, name='index'),
    url(r'^home/?$', views.index, name='home'),
    url(r'^ng/home/?$', views.home, name='home'),

    url(r'^config/?$', views.index, name='configure'),
    url(r'^ng/config/?$', views.configure, name='configure'),

    url(r'^config/results/?$', views.index, name='results'),
    url(r'^ng/config/results/?$', views.results, name='results'),

    # ====================>>>>>>>> APIs <<<<<<<<====================
    url(r'^api/snmp/create/?$', views.api_snmp, name='api_snmp'),

    url(r'^api/dns/create/?$', views.api_dns, name='api_dns'),

    url(r'^api/tacacs/create/?$', views.api_tacacs, name='api_tacacs'),

    url(r'^api/ntp/create/?$', views.api_ntp, name='api_ntp'),

    url(r'^api/syslog/create/?$', views.api_syslog, name='api_syslog'),

]
