# Access Control Policies

Every network has one policy. It is a JSON document of **accept** rules, and
anything not accepted is dropped (default deny). A new network starts with an
allow-all default:

```json
{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}
```

Tighten it before you share a network with others.

## How it's enforced

The server compiles the policy separately for each device into two things:

1. **Peer list.** A device only learns about peers it can reach or that can reach
   it. Other devices' keys and endpoints are never sent to it.
2. **Inbound packet filter.** Each device enforces this on traffic it *receives*.
   A compromised sender can't skip a check that runs on the receiver.

Replies to connections a device opened are always allowed (connection
tracking), so `A → B:22` works without a reverse rule. WireGuard's cryptokey
routing guarantees a peer can't forge another peer's source address.

Policy changes reach devices on their next map refresh: within about 10 s now,
and instantly once Phase 5's push stream lands.

## Syntax

```json
{
  "groups": {
    "group:admins": ["alice@example.com", "bob@example.com"]
  },
  "hosts": {
    "office-lan": "192.168.10.0/24"
  },
  "acls": [
    {"action": "accept", "src": ["group:admins"],     "dst": ["*:*"]},
    {"action": "accept", "src": ["autogroup:member"], "dst": ["tag:web:80,443"], "proto": "tcp"},
    {"action": "accept", "src": ["tag:web"],          "dst": ["tag:db:5432"]},
    {"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}
  ]
}
```

### Selectors

| Selector | Matches |
|---|---|
| `*` | every device and address |
| `alice@example.com` | untagged devices owned by that user |
| `group:name` | untagged devices owned by any user in the group (groups contain emails; no nesting) |
| `tag:name` | devices with that tag. **A tagged device has no user identity**: it matches only tag rules, `*` and address rules |
| `autogroup:member` | all untagged (user-owned) devices |
| `autogroup:tagged` | all tagged devices |
| `autogroup:self` | *dst only*: devices owned by the same user as the source |
| host alias | an entry from `hosts` |
| `100.64.0.5`, `10.0.0.0/8`, `[fd7a::1]` | addresses and prefixes |

### Destinations and ports

A `dst` entry is `selector:ports`, split at the last colon:

* ports are `*`, `22`, `80,443` or `8000-8100`
* IPv6 literals must be bracketed: `[fd7a::1]:22`
* `proto` is optional and may be `tcp`, `udp` or `icmp`; omitted means any protocol
* a rule with specific ports does **not** allow ICMP (ping); use port `*` for that

Tags are assigned through auth keys or by an admin (`PATCH …/devices/{id}`).

## Editing safely

```bash
# Read (note "version")
curl -s -b jar $B/networks/$NID/acl
# Try a draft without saving: may laptop reach db on 5432?
curl -s -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
  -d '{"src":"laptop","dst":"db","proto":"tcp","port":5432,"policy":{…draft…}}' $B/networks/$NID/acl/test
# Save, passing the version you read; a 409 stale_version means someone else saved first
curl -s -b jar -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' -X PUT \
  -d '{"version":3,"policy":{…}}' $B/networks/$NID/acl
```

Validation reports every problem at once, for example
`acls[2].dst[0]: undefined group "group:ops"`. Every saved version is kept in
`acl_policy_history`.
