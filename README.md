# GreenArrow Firewall Setup with UFW

A practical Ubuntu/Debian host-firewall guide for GreenArrow Engine and Studio. Allow administration first, open the services you actually use, then enable UFW. Optional services get explicit source restrictions.

**Start with the port table and work through the steps.** This replaces the old one-liner, which enabled UFW before allowing SSH and exposed database and monitoring ports publicly. Commands assume Bash and a normal host installation; custom ports, containers, clusters, and upstream firewalls need their own rules.

## Choose the incoming rules

| Service | TCP port | Who should connect? |
| --- | --- | --- |
| Incoming SMTP, bounces, complaints | 25 | Public Internet when this host receives them |
| SMTP submission | 587 | Your authorized injection clients |
| QMQP / streaming QMQP | 628 / 629 | Your authorized injection clients, if used |
| POP3 | 110 | Intended POP clients, if used |
| HTTP / HTTPS | 80 / 443 | Public for tracking/Studio as needed; otherwise restrict management access |
| SSH | Your actual port | Your trusted administrator IPs or VPN ranges |
| PostgreSQL | 5432 | Explicit trusted sources only, if required |
| Nagios monitoring | 5666 | Your monitoring source only, if used |

These defaults follow [GreenArrow's firewall requirements](https://www.greenarrowemail.com/docs/greenarrow-engine/Getting-Started/Firewall-Configuration). Confirm the actual listeners on your server. Opening a port does not configure TLS, authentication, or application permissions.

## 1. Install and inspect

Keep your current SSH session open and have your provider's console available. Check the upstream/cloud firewall too. **A source address is the public IP or CIDR of the connecting administrator/client, not the mail server's own IP.**

```bash
sudo apt-get update
sudo apt-get install --yes ufw
sudo ufw status verbose
sudo ufw show added
sudo ss -lntup
```

Back up existing UFW configuration before changing it:

```bash
sudo tar -C /etc -czf "/root/ufw-before-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" ufw default/ufw
grep '^IPV6=' /etc/default/ufw
```

If the host uses IPv6, keep UFW's IPv6 handling enabled (`IPV6=yes`) and plan IPv6 access rules as well. UFW's standard before-rules already permit the loopback interface for IPv4 and IPv6. Preserve those rules; adding a broad source-only localhost rule is unnecessary on a standard installation.

If UFW is already active, changes take effect as you make them. Review existing allow/deny rules and any custom before-rules first. This guide does not reset or replace them, so existing broad allow rules can still expose services.

## 2. Allow your real SSH port first

Do not assume SSH listens on 22. Confirm it with `ss` and your SSH configuration, then enter the actual port and trusted source when prompted. The variables below remain available in the same Bash session for later examples.

```bash
read -r -p 'Actual SSH listening port: ' SSH_PORT
read -r -p 'Trusted administrator IP or CIDR: ' ADMIN_SOURCE
: "${SSH_PORT:?Enter the actual SSH port}"
: "${ADMIN_SOURCE:?Enter your trusted administrator source}"

sudo ufw --dry-run prepend allow in proto tcp from "$ADMIN_SOURCE" to any port "$SSH_PORT" comment 'SSH administration'
sudo ufw prepend allow in proto tcp from "$ADMIN_SOURCE" to any port "$SSH_PORT" comment 'SSH administration'
```

**Stop if either UFW command fails.** The dry run validates the rule without applying it. `prepend` works with an empty ruleset and places the rule before existing user rules of the same IP family, avoiding an earlier user deny rule taking precedence. Repeat for other administrator sources, including IPv6 sources if applicable. Do not use `any` or a catch-all CIDR as the administrator source unless public SSH access is your deliberate policy.

## 3. Set policies and add required public services

Allow outgoing traffic unless you maintain a complete egress policy. GreenArrow also needs outbound DNS over **both UDP and TCP**, SMTP, updates, relay connections, and any integration services you use; outbound-only needs do not justify opening those ports inbound.

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in 25/tcp comment 'Incoming SMTP and bounces'
```

If this host serves public tracking, Studio, or other required web endpoints, add:

```bash
sudo ufw allow in 80/tcp comment 'GreenArrow HTTP'
sudo ufw allow in 443/tcp comment 'GreenArrow HTTPS'
```

Otherwise, keep management HTTP/HTTPS limited to trusted sources using the pattern in the next section. A public tracking listener may also serve management routes; use [GreenArrow HTTP URI filtering](https://www.greenarrowemail.com/docs/greenarrow-engine/Network-Services/HTTP-Server) or a correctly configured reverse proxy to separate them.

## 4. Add only the optional services you use

For SMTP injection, enter a trusted sending application's IP or CIDR. Repeat for each authorized source:

```bash
read -r -p 'Trusted SMTP injection client IP or CIDR: ' SMTP_SOURCE
: "${SMTP_SOURCE:?Enter a trusted injection client source}"
sudo ufw allow in proto tcp from "$SMTP_SOURCE" to any port 587 comment 'SMTP injection'
```

For QMQP, streaming QMQP, or POP3, set a service-specific client source and run **only the applicable rule(s)**:

```bash
read -r -p 'Trusted optional-service client IP or CIDR: ' CLIENT_SOURCE
: "${CLIENT_SOURCE:?Enter a trusted client source}"
sudo ufw allow in proto tcp from "$CLIENT_SOURCE" to any port 628 comment 'QMQP injection'
sudo ufw allow in proto tcp from "$CLIENT_SOURCE" to any port 629 comment 'Streaming QMQP injection'
sudo ufw allow in proto tcp from "$CLIENT_SOURCE" to any port 110 comment 'POP3 clients'
```

Do not expose QMQP or POP3 just because a service is installed. Confirm encryption and authentication requirements for any client-facing service before exposing it.

### Optional GreenArrow support access

The following source addresses are published in GreenArrow's linked firewall documentation, reviewed on **2026-10-15**. Confirm them with GreenArrow before use; apply each rule only for a service you have arranged:

```bash
# Technical support SSH, on your actual SSH port.
sudo ufw allow in proto tcp from 205.159.93.6 to any port "$SSH_PORT" comment 'GreenArrow support SSH'

# Managed-backup SSH, if that service is enabled.
sudo ufw allow in proto tcp from 104.196.149.69 to any port "$SSH_PORT" comment 'GreenArrow managed backups'

# Optional deliverability consulting database access.
sudo ufw allow in proto tcp from 205.159.93.6 to any port 5432 comment 'GreenArrow consulting PostgreSQL'

# Optional GreenArrow monitoring.
sudo ufw allow in proto tcp from 205.159.93.185 to any port 5666 comment 'GreenArrow monitoring'
```

These are service-specific openings, not a blanket vendor whitelist. Never make 5432 or 5666 globally accessible just to match this guide.

## 5. Review, enable, and test a fresh connection

Review configured rules before enabling. `show added` lists configured user rules even while UFW is inactive; `status numbered` becomes useful once active.

```bash
sudo ufw show added
sudo ufw enable
sudo ufw status verbose
sudo ufw status numbered
```

Keep the normal `enable` confirmation. From another terminal, **open a new SSH connection using the actual port and allowed source** before closing the existing session. An established connection alone does not prove the new rule allows reconnection. Test required mail, submission, web, and monitoring services from their intended sources, including IPv6 where applicable.

UFW applies normal CLI rule changes immediately when active; an extra reload is not needed after each rule. Changes to rule files or other manual configuration may require a reload.

### Upgrading from the old guide

Adding a narrow allow rule does not cancel an existing public allow rule. Add replacements and verify new administration access first, then inspect `sudo ufw status numbered` and remove obsolete broad rules.

For the exact unrestricted database and monitoring rules from the old guide:

```bash
sudo ufw delete allow 5432/tcp
sudo ufw delete allow 5666/tcp
```

Remove unused public 587, 628, 629, and 110 rules the same way, after confirming client access through the replacement source rules. Remove the original public `allow 22/tcp` only after a fresh SSH login through the restricted rule succeeds. If deleting by rule number, refresh the listing after every deletion because numbers change. A narrow deny added after a broad allow is not a replacement for removing that allow.

If locked out, use your provider's console to inspect the rules. Emergency `sudo ufw disable` stops UFW filtering; it is a recovery action and leaves the saved rules in place for repair.

## Optional: configure and verify Fail2Ban

Installing Fail2Ban does not establish that the intended jails are enabled, read the correct logs, or ban the correct SSH port. For an Ubuntu/Debian system using the systemd journal:

```bash
sudo apt-get install --yes fail2ban python3-systemd
sudoedit /etc/fail2ban/jail.d/greenarrow-sshd.local
```

Add the following, replacing `YOUR_SSH_PORT` with the actual numeric port. If the file already exists, merge your settings instead of discarding its contents:

```ini
[sshd]
enabled = true
port = YOUR_SSH_PORT
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
```

Check the merged configuration before restarting, then verify the running SSH jail:

```bash
sudo fail2ban-client -t &&
sudo systemctl enable fail2ban &&
sudo systemctl restart fail2ban &&
sudo fail2ban-client status sshd
```

The SSH jail protects SSH, not GreenArrow SMTP authentication. For SMTP failures, consult [GreenArrow's Fail2Ban integration](https://www.greenarrowemail.com/docs/greenarrow-engine/Server-Management-and-Backups/fail2ban-Integration). Its examples target RHEL/iptables; adapt and test the log backend and ban action for your environment before deployment. Keep distribution `.conf` files intact and put local overrides in `.local` files.

## Scope and verification

UFW is a host firewall. Cloud security groups, routers, container-published ports, reverse proxies, load balancers, and GreenArrow cluster links require separate review. In particular, do not assume a host INPUT rule governs traffic forwarded to a container.

CI checks Bash syntax in this README and validates its firewall mutation commands using **real `ufw --dry-run`** on disposable Ubuntu runners. It does not apply rules or prove remote reachability. The repository's Git history was also scanned for secrets during this update.

Sources reviewed on 2026-10-15:

- [GreenArrow firewall configuration](https://www.greenarrowemail.com/docs/greenarrow-engine/Getting-Started/Firewall-Configuration)
- [Ubuntu Server firewall guide](https://ubuntu.com/server/docs/how-to/security/firewalls/)
- [UFW command reference](https://manpages.debian.org/bookworm/ufw/ufw.8.en.html)
- [Fail2Ban upstream configuration](https://github.com/fail2ban/fail2ban/blob/master/config/jail.conf)
- [GreenArrow Fail2Ban integration](https://www.greenarrowemail.com/docs/greenarrow-engine/Server-Management-and-Backups/fail2ban-Integration)
