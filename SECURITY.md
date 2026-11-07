# Security policy

AccessGuard handles identity data, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue**. Use GitHub's private vulnerability reporting
(**Security → Report a vulnerability** on this repository) and include:

- what you found and where (file, endpoint or command);
- steps to reproduce;
- the impact you think it has.

You should get an acknowledgement within five working days.

## Design commitments

- AccessGuard never writes to a Microsoft Entra tenant. Any change that would add a write path is out of scope.
- The Graph bearer token is only ever sent to `https://graph.microsoft.com/`.
- Scan snapshots stay on the machine running AccessGuard; there is no telemetry.

## Operator responsibilities

- Keep `.env`, certificates and the `data/` directory private.
- Use a certificate or a short-lived secret, and rotate it.
- Do not expose the dashboard to the internet without an authenticating reverse proxy.
