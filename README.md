# Fail2Ban middleware plugin for traefik reverse proxy

![Continuous Integration Status](https://github.com/juitde/traefik-plugin-fail2ban/actions/workflows/ci.yml/badge.svg?branch=main)

This plugin is a small but growing implementation of a fail2ban instance as a middleware plugin for traefik. It is
inspired by other implementations similar in the goal but is tailored to our needs.

Inspirations taken from:
- https://github.com/tomMoulard/fail2ban
- https://github.com/safing/scanblock

## Installation

Installation instructions are provided via the [traefik Plugin Catalog](https://plugins.traefik.io/plugins/).

## Configuration

All configuration options may be specified either in config files or as CLI parameters.

### Always allowing or blocking certain IPs(/IP-ranges)

There can be configured certain ip addresses or ranges which are either always allowed or always denied access.
Blocking always takes precedence before allowing access and allowing access takes precedence before executing other
fail2ban rules.

```yaml
testData:
    alwaysAllowed:
        ip: "::1,127.0.0.1"
    alwaysDenied:
        ip: "192.168.0.0/24"
```

### Restricting logging messages

In order to help managing the use of this plugin the level of logged messages can be adjusted.

```yaml
testData:
    logLevel: "INFO"
```

### Fail2Ban rules

The ultimate goal is to support any rule matcher fail2ban supports themselves but implementation follows the direct
needs of our projects.

Currently the implemented settings consist of:

```yaml
testData:
    rules:
        banTime: "3h"
        findTime: "10m"
        maxRetries: 4
        response:
            statusCodes: "400,401,403-499"
```

## Processing requests

Prior to executing the defined rules if the Remote IP is in the `alwaysDenied`-list the request will be immediately
denied. This applies for the `alwaysAllowed`-list accordingly.

In the first request from an unknown IP address they are added to the pool starting the `findTime` timer:

In every subsequent request (while the findTime is not exceeded) the IP address counter in the pool is incremented
and the rules are checked.

# How to develop in this project

- First clean install vendor dependencies: `make clean vendor`
