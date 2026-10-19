# Registration-ticket implementation

The unified executable wires identityd.Client into cli.RunWithService and the
caller resolver. The client uses Call's kernel-authenticated socket; client PID
or role labels never select service authority.

A configured service opens its private SQLite store and uses a service-side
HumanAuthorizer. Its administrator supplies a separate human UID and full live
login-session identity in the protected service definition. The peer must have
a real terminal, no service-recorded identity and kernel ancestry to that root.
The CLI pre-check is supplementary. The issue RPC persists only the digest,
scope, expiry and use time and returns the raw value once.

RegistrationVerifier[identityd.Peer, identityd.Grant] implements TicketVerifier.
Its strict JSON envelope contains role and value only. Trusted configuration and
actual peer ancestry supply the dedicated parent grant before atomic consume.
The service maps ticket.Refusal to its safe refusal type so exact first lines
survive. Successful consume records the trusted peer within the same transaction.
The human's status exposes that consuming peer; a used ticket warns of possible
theft. One day of expired diagnostics is retained before authorized-issue pruning.

With a configured service, new local supervisor sessions and role files are
neither written nor trusted. Legacy activation imports an administrator-frozen
live-process snapshot once. Without a service, the explicitly noticed 0.7.0
open-registration path remains available for R26 compatibility.

The ticket-reuse mutation removes the real SQL unused predicate. The
ticket-human-pty mutation restores the prior human rule at the service boundary.
They are inert in release builds. See e2e-rows/TICKET.md for the real CLI/PTY,
lane start/adoption, legacy and mutation rows and required Linux evidence.
