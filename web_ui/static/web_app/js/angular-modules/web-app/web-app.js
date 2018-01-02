
// >>>>>>>> Global Variables <<<<<<<<

var appModule = angular.module('appModule',['ngRoute','ngAnimate'])

// >>>>>>>> Filters <<<<<<<<

// Tells if an object is instance of an array type. Used primary within ng-templates
appModule.filter('isArray', function() {
  return function (input) {
    return angular.isArray(input);
  };
});


// Add new item to list checking first if it has not being loaded and if it is not null.
// Used primary within ng-templates
appModule.filter('append', function() {
  return function (input, item) {
    if (item){
        for (i = 0; i < input.length; i++) {
            if(input[i] === item){
                return input;
            }
        }
        input.push(item);
    }
    return input;
  };
});

// Remove item from list. Used primary within ng-templates
appModule.filter('remove', function() {
  return function (input, item) {
    input.splice(input.indexOf(item),1);
    return input;
  };
});

// Capitalize the first letter of a word
appModule.filter('capitalize', function() {

  return function(token) {
      return token.charAt(0).toUpperCase() + token.slice(1);
   }
});

// Replace any especial character for a space
appModule.filter('removeSpecialCharacters', function() {

  return function(token) {
      return token.replace(/#|_|-|$|!|\*/g,' ').trim();
   }
});

appModule.filter('capitalize', function() {
    // Capitalize the first letter of a word
  return function(token) {
      return token.charAt(0).toUpperCase() + token.slice(1);
   }
});

// >>>>>>>> Configurations <<<<<<<<

// Application routing
appModule.config(function($routeProvider, $locationProvider){
    // Maps the URLs to the templates located in the server
    $routeProvider
        .when('/', {templateUrl: 'ng/home'})

        .when('/config', {templateUrl: 'ng/config'})

        .when('/config/results', {templateUrl: 'ng/config/results'})

    $locationProvider.html5Mode(true);
});

// To avoid conflicts with other template tools such as Jinja2, all between {a a} will be managed by ansible instead of {{ }}
appModule.config(['$interpolateProvider', function($interpolateProvider) {
  $interpolateProvider.startSymbol('{a');
  $interpolateProvider.endSymbol('a}');
}]);

// >>>>>>>> Factories <<<<<<<<

// The notify factory allows services to notify to an specific controller when they finish operations
appModule.factory('NotifyingService' ,function($rootScope) {
    return {
        subscribe: function(scope, event_name, callback) {
            var handler = $rootScope.$on(event_name, callback);
            scope.$on('$destroy', handler);
        },

        notify: function(event_name) {
            $rootScope.$emit(event_name);
        }
    };
});

// The auth notify factory allows other components subscribe and being notified when authentication is successful
appModule.factory('AuthNotifyingService', function($rootScope) {
    return {
        subscribe: function(scope, callback) {
            var handler = $rootScope.$on('notifying-auth-event', callback);
            scope.$on('$destroy', handler);
        },

        notify: function() {
            $rootScope.$emit('notifying-auth-event');
        }
    };
});

// This factory adds the token to each API request
appModule.factory("authInterceptor", function($rootScope, $q, $window){
    return {
        request: function(config){
            config.headers = config.headers  || {};
            if ($window.sessionStorage.token){
                config.headers.Authorization = 'Bearer ' + $window.sessionStorage.token;
            }
            return config;
        },
        responseError: function(rejection){
            if (rejection.status === 401){
                //Manage common 401 actions
            }
            return $q.reject(rejection);
        }
    };
});

// >>>>>>>> Controllers <<<<<<<<

// Location controller is in charge of managing the routing location of the application
appModule.controller('LocationController', function($scope, $location){
     $scope.go = function ( path ) {
        $location.path( path );
    };
});

// App controller is in charge of managing all services for the application
appModule.controller('AppController', function($scope, $location, $http){
    // ====================>>>>>>>> variables <<<<<<<<====================

    $scope.apic = {}
    $scope.apic.snmp = {}
    $scope.apic.snmp.users = []
    $scope.apic.ntp = {}
    $scope.apic.syslog = {}
    $scope.apic.tacacs = {}
    $scope.apic.dns = {}
    $scope.n9k = {}

    $scope.state = {}
    $scope.state.snmp = {}

    $scope.state.ntp = {}
    $scope.state.syslog = {}
    $scope.state.tacacs = {}
    $scope.state.dns = {}

    // ====================>>>>>>>> Methods <<<<<<<<====================

    $scope.findConfiguration = function(){

        $scope.apic.snmp = {}
        $scope.apic.snmp.users = []
        $scope.apic.ntp = {}
        $scope.apic.syslog = {}
        $scope.apic.tacacs = {}
        $scope.apic.dns = {}

        // SNMP Server
        // Based on the command:
        // snmp-server host IP traps version 2c COMMUNITY udp-port PORT
        var snmp_config_text = 'snmp-server host '
        var snmp_config_index = $scope.n9k.running_config.search(snmp_config_text)
        if(snmp_config_index != -1){
            $scope.apic.snmp.ip = $scope.n9k.running_config.substring(snmp_config_index ,snmp_config_index + 300).split('\n')[0].split(' ')[2]
            $scope.apic.snmp.port = $scope.n9k.running_config.substring(snmp_config_index ,snmp_config_index + 300).split('\n')[0].split('udp-port')[1].trim()
            $scope.apic.snmp.version = $scope.n9k.running_config.substring(snmp_config_index ,snmp_config_index + 300).split('\n')[0].split('version')[1].split(' ')[1].trim()
            if ($scope.apic.snmp.version == '2c' || $scope.apic.snmp.version == '1'){
                $scope.apic.snmp.community_name = $scope.n9k.running_config.substring(snmp_config_index ,snmp_config_index + 300).split('\n')[0].split($scope.apic.snmp.version)[1].split(' ')[1].trim()
            }
            else if ($scope.apic.snmp.version == '3'){
                $scope.apic.snmp.security_level = $scope.n9k.running_config.substring(snmp_config_index ,snmp_config_index + 300).split('\n')[0].split(' ' + $scope.apic.snmp.version + ' ')[1].split(' ')[0].trim()
                $scope.apic.snmp.community_name = $scope.n9k.running_config.substring(snmp_config_index ,snmp_config_index + 300).split('\n')[0].split($scope.apic.snmp.security_level)[1].split(' ')[1].trim()
            }
        }

        // SNMP Users
        var snmp_users = $scope.n9k.running_config.match(/snmp-server user .*/g)
        if (snmp_users){
            for (i = 0; i < snmp_users.length; i++) {
                var username = snmp_users[i].split("snmp-server user ")[1].split(" ")[0]
                var priv_type = snmp_users[i].split(" priv ")[1].split(" ")[0]
                var auth_type = snmp_users[i].split(" auth ")[1].split(" ")[0]
                if(priv_type == "aes-128"){
                    $scope.apic.snmp.users.push({"priv_type": priv_type, "username": username, "auth_type": auth_type})
                }
                else{
                    $scope.apic.snmp.users.push({"priv_type": "none", "username": username, "auth_type": auth_type})
                }
            }
        }


        // NTP Server
        // Based on the command:
        // ntp server IP
        var ntp_config_text = 'ntp server '
        var ntp_config_index = $scope.n9k.running_config.search(ntp_config_text)
        if(ntp_config_index != -1){
            $scope.apic.ntp.ip = $scope.n9k.running_config.substring(ntp_config_index ,ntp_config_index + 300).split('\n')[0].split(' ')[2]
        }

        // SysLog Server
        // Based on the command:
        // logging server IP
        var syslog_config_text = 'logging server '
        var syslog_config_index = $scope.n9k.running_config.search(syslog_config_text)
        if(syslog_config_index != -1){
            $scope.apic.syslog.ip = $scope.n9k.running_config.substring(syslog_config_index ,syslog_config_index + 300).split('\n')[0].split(' ')[2]
        }

        // Tacacs+ Server
        // Based on the command:
        // tacacs-server host IP key 7 KEY port PORT
        var tacacs_config_text = 'tacacs-server host '
        var tacacs_config_index = $scope.n9k.running_config.search(tacacs_config_text)
        if(tacacs_config_index != -1){
            $scope.apic.tacacs.ip = $scope.n9k.running_config.substring(tacacs_config_index ,tacacs_config_index + 300).split('\n')[0].split(' ')[2]
        }

        // DNS Server
        // Based on the command:
        // ip name-server IP
        var dns_config_text = 'ip name-server '
        var dns_config_index = $scope.n9k.running_config.search(dns_config_text)
        if(dns_config_index != -1){
            $scope.apic.dns.ip = $scope.n9k.running_config.substring(dns_config_index ,dns_config_index + 300).split('\n')[0].split(' ')[2]
        }
    }


    $scope.createNTP = function(){
        $scope.state.ntp.result = 'loading'
        $http
            .post('api/ntp/create', {'apic': $scope.apic })
            .then(function (response, status, headers, config){
                $scope.state.ntp.result = 'ok'
            })
            .catch(function(response, status, headers, config){
                $scope.state.ntp.result = 'error'
                $scope.state.ntp.error = response.data.message
            })
            .finally(function(){
            })
    }

    $scope.createDNS = function(){
        $scope.state.dns.result = 'loading'
        $http
            .post('api/dns/create', {'apic': $scope.apic })
            .then(function (response, status, headers, config){
                $scope.state.dns.result = 'ok'
            })
            .catch(function(response, status, headers, config){
                $scope.state.dns.result = 'error'
                $scope.state.dns.error = response.data.message
            })
            .finally(function(){
            })
    }

    $scope.createSyslog = function(){
        $scope.state.syslog.result = 'loading'
        $http
            .post('api/syslog/create', {'apic': $scope.apic })
            .then(function (response, status, headers, config){
                $scope.state.syslog.result = 'ok'
            })
            .catch(function(response, status, headers, config){
                $scope.state.syslog.result = 'error'
                $scope.state.syslog.error = response.data.message
            })
            .finally(function(){
            })
    }

    $scope.createTacacs = function(){
        $scope.state.tacacs.result = 'loading'
        $http
            .post('api/tacacs/create', {'apic': $scope.apic })
            .then(function (response, status, headers, config){
                $scope.state.tacacs.result = 'ok'
            })
            .catch(function(response, status, headers, config){
                $scope.state.tacacs.result = 'error'
                $scope.state.tacacs.error = response.data.message
            })
            .finally(function(){
            })
    }

    $scope.createSNMP = function(){
        $scope.state.snmp.result = 'loading'
        $http
            .post('api/snmp/create', {'apic': $scope.apic })
            .then(function (response, status, headers, config){
                $scope.state.snmp.result = 'ok'
            })
            .catch(function(response, status, headers, config){
                $scope.state.snmp.result = 'error'
                $scope.state.snmp.error = response.data.message
            })
            .finally(function(){
            })
    }

    $scope.sendConfiguration = function(){

        $scope.createSNMP();
        $scope.createDNS();
        $scope.createTacacs();
        $scope.createNTP();
        $scope.createSyslog();

        $location.path('config/results');
    }

    // ====================>>>>>>>> Events <<<<<<<<====================

    $scope.$on('$viewContentLoaded', function(){
        setTimeout(function(){

            $('.selectpicker').selectpicker();

            $('.selectpicker')
                .change(function(){
                    setTimeout(function(){$('.selectpicker').selectpicker('refresh')},500);
                });
        }
        ,1000);

    });

});
