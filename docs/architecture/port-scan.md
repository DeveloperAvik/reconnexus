# Port scanning (stage 15)

Identifies open TCP ports and the services behind them for addresses that resolve from in-scope hosts.

## Authorization
- Requires the `PORT_SCAN` capability in the scope policy. Without it the stage is not planned at all
  (`ScanService.createScan`), and a worker job for it is `BLOCKED`. Add it to `authorization.capabilities`.
- Targets are `(host, address)` pairs from DNS `resolves_to` relationships. The worker checks each pair with
  the scope engine using the host and the resolved address, so a name that resolves to loopback/private/
  metadata space is denied unless the policy lists it and grants `INTERNAL_NETWORK`.
- Shared infrastructure: an in-scope hostname behind a CDN or shared host resolves to addresses you do not
  own. Review scope before enabling `PORT_SCAN` on such targets; the stage does not detect CDN ownership.

## Execution
`nmap -sT -Pn -n -sV --version-light --open -T3 --max-retries 1 --host-timeout 600s -p <ports>
--max-rate <requestsPerSecond> -oX - <ips>`, IPv4 and IPv6 in separate invocations. No scripts, OS
detection or raw-packet scan types, so it needs no privileges. Default ports: a fixed list of common
web, remote-access, database, mail and management services (`defaultPortList` in
`workers/internal/discovery/nmap.go`); override with `--ports 80,443,8000-8100`.

## Output
`PORT_OBSERVATION` records become `SERVICE` assets keyed `ip:port/tcp`, with `exposes_port`
relationships from the IP and the host, and `port-observation` observations. Product and version are
nmap's service-detection claims, not verified facts. Closed and unscanned ports are not recorded, so
absence is not evidence a port is closed. Query with `rn ports <scanId>`.
