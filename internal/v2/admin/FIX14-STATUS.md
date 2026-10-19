# First-install and enrollment follow-up

The first-install receipt read now uses the frozen Events contract without
a caller limit. It requires the first event's exact sequence, publication ID,
kind, configuration, operation and marker payload. Later events are ignored.
The component event store follows Since and returns all matching fixture
events; tests cover a later event and a foreign first sequence.

The mutation input roots add only the two CLI dependencies internal/jsontext
and internal/typesafe. Existing owned-file exceptions and doctor control
assertions remain. The runner still rejects build failures and missing tests.

InitialEnrollmentValidator.ValidateEnrollment now checks the produced
HumanEnrollment inventory and retains its private ValidatedRegistration on
the actual native channel. Both the interface and concrete registration
entry use that same handoff. Producer inputs, retained signed request bytes,
returned installation bytes and the retained installation use independent
copies. The store's original guard and durable read-back remain required.

The native helper's complete reply now checks the original challenge ID and
bounded artifact evidence pin in addition to the existing ceremony and
operation fields. Regression controls target direct-interface handoff loss,
foreign challenge and malformed evidence digest acceptance. The prior
protocol negative now selects a distinct protocol after codec alignment.

This follow-up does not implement the composed service's separate listener
dispatch or replace the service/store owner stubs. The earlier FIX13 status
and installer README retain those integration requirements. Runtime Linux
red/candidate and native installed publication remain acceptance requirements.
