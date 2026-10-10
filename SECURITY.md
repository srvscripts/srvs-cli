# Security policy

Please report security problems in `srvs` privately to **security@srvscripts.com** rather than in a public issue.
Include the version (`srvs version`), the command you ran and what happened. We aim to answer within three working days.

`srvs` only makes the network requests a check needs (DNS queries, TLS handshakes and HTTP requests to the targets you
name, and blacklist DNS lookups). It sends nothing to srvscripts.com and has no telemetry.
