# Protocol coverage

kolo-moq implements MoQ Transport, draft-ietf-moq-transport-22. Section
numbers refer to that draft. This page lists what is supported, what is
answered with an error and what is not done.

## Binding to Kolo connections

Kolo connections are QUIC with ALPN `kolo/0` and no datagrams, so each
control stream starts with the preface `07 6d 6f 71 74 2d 32 32`: the
draft's varint 7 and `moqt-22`. A peer whose control stream starts
otherwise is closed with `PROTOCOL_VIOLATION` and the session returns
`ErrVersion`. Everything after the preface is draft-22: SETUP, then GOAWAY
on the control stream, one bidirectional stream per request, and
unidirectional subgroup and fetch streams. The dialer is the MoQT client
(even Request IDs), the acceptor the server (odd).

## Supported

- SETUP: MOQT_IMPLEMENTATION sent; PATH and AUTHORITY accepted from a
  client and ignored, refused from a server; MAX_REQUEST_UPDATES obeyed, as
  at most one REQUEST_UPDATE per request is outstanding; authorization
  tokens checked for form, unknown options ignored.
- Messages: GOAWAY, SUBSCRIBE, SUBSCRIBE_OK, REQUEST_UPDATE, REQUEST_OK,
  REQUEST_ERROR, PUBLISH_DONE, PUBLISH_STATE_NOTIFY (read), FETCH,
  FETCH_OK, TRACK_STATUS, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, NAMESPACE
  and NAMESPACE_DONE.
- Data: subgroup streams with every header form, fetch streams with End of
  Range markers, padding streams; object properties, kept end to end; object
  status.
- Location filters and FILL_PARAMETERS; subscriber and publisher priority
  and group order.
- SUBGROUP_DELIVERY_TIMEOUT and OBJECT_DELIVERY_TIMEOUT; expired streams
  are reset with `DELIVERY_TIMEOUT`. An object's timeouts are read at the top
  level of its properties and inside Immutable Properties, which processors
  must search (section 10.7); the draft assigns type 0x02 to
  OBJECT_DELIVERY_TIMEOUT there as well, so a Key ID must use another type
  (the Kolo profile of package `secobj` uses 0x78, from the application
  range of section 8.4).
- Kolo reserves the first namespace field `kolo-keys` (not part of the
  draft): `TrackOptions.Readers` limits who may SUBSCRIBE to, FETCH or ask
  TRACK_STATUS of a track, and a relay refuses every request under that
  namespace.
- `RoomPolicy` implements the rule of section 15.3.3 that a relay ensures a
  client cannot publish to namespaces of another identity, for rooms named
  by a namespace prefix.

## Answered with an error

- PUBLISH and SUBSCRIBE_TRACKS get `REQUEST_ERROR NOT_SUPPORTED`, and so
  does REQUEST_UPDATE of a namespace prefix.
- Range filters are refused with `INVALID_FILTER` (MAX_FILTER_RANGES is 0).
  A zero-length filter means no filter and is accepted.
- This side keeps no authorization token aliases (MAX_AUTH_TOKEN_CACHE_SIZE
  is 0), so REGISTER closes the session with `AUTH_TOKEN_CACHE_OVERFLOW`,
  USE_ALIAS and DELETE with `UNKNOWN_AUTH_TOKEN_ALIAS`, as the draft
  requires. USE_VALUE tokens are checked for form and otherwise unused:
  authorization is by the peer's key through `Config.Authorize`.
- Requests for the `.` and `.session` namespaces get `DOES_NOT_EXIST`.
- PUBLISH_NAMESPACE under `kolo-keys` gets `UNAUTHORIZED`, and so does every
  request under it at a relay; a track with `Readers` gets `DOES_NOT_EXIST` for
  other peers.
- RENDEZVOUS_TIMEOUT is parsed and ignored: a SUBSCRIBE for a namespace
  nobody announced gets `DOES_NOT_EXIST` at once.
- NEW_GROUP_REQUEST is honored in REQUEST_UPDATE (see "Asking for a new
  group" in the guide). `Subscription.RequestNewGroup` sends it with value 0
  when no group arrived, else the largest group received plus one; a
  publisher ignores a value not above its largest group, signals
  `TrackWriter.NewGroupRequests` at most once per second per track,
  and a relay passes the request to the publisher of a relayed track.

## Not done

- The relay subscribes to one publisher per track (the one with the longest
  matching namespace, the first announcer on a tie), not to every matching
  publisher as section 7.6 asks. A namespace has one announcer, because a
  relay refuses an announcement of a namespace equal to or under another
  peer's, so the merge of several publishers of one track never applies.
- RENDEZVOUS_TIMEOUT is not honored.
- PUBLISH, SUBSCRIBE_TRACKS, range
  filters, authorization token aliases and namespace-prefix updates are
  refused or ignored as listed above.
- `TrackWriter` writes one subgroup per group (subgroup 0); receiving
  accepts any layout.
- A subscriber that is not a relay checks the malformed-track rules that
  one object shows (sections 3.7, 10.7 to 10.9); the rules that need state
  across objects (section 12.1 items 1 to 7) are checked by the relay cache
  only.
- The relay does not cache or check what a FETCH response says about the end
  of the track (section 12.1 item 5, last sentence).
- SUBGROUP_DELIVERY_TIMEOUT ends when the subgroup's last byte and FIN are
  handed to the transport, not at acknowledgement: kolo-transport reports no
  acknowledgements.

## Malformed tracks (section 12.1)

A relay checks the rules its cache can see: a repeated object that differs
(payload, subgroup, priority, status, immutable properties or delivery
mode), another priority in a subgroup, objects after the end of a subgroup,
group or track, and subgroup streams that end at different objects. It does
not cache the object that breaks a rule, ends downstream subscriptions with
PUBLISH_DONE `MALFORMED_TRACK`, resets open fetch streams with
`MALFORMED_TRACK` and cancels the upstream subscription.

## Track layout

A track written by a `TrackWriter` has one subgroup per group, subgroup 0;
each group ends with an End of Group object and the track with End of
Track. Object properties are always announced in the subgroup header, so an
object without properties costs one byte.

## Joining a track

Draft-22 has no joining FETCH. A subscriber joins at the current group with
a SUBSCRIBE whose Location Filter starts at the Next Object and whose
FILL_PARAMETERS select a relative start of one group (section 3.5). That is
`JoinCurrentGroup`; the fill fetch stream and the live subgroup streams
feed the same subscription. A standalone FETCH of the newest groups uses
the relative start filter (`FetchOptions.RecentGroups`).

## References

- [Media over QUIC Transport, draft-ietf-moq-transport-22](https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22)
  (Internet-Draft, October 2026, expires 4 April 2027).
  Takes: the whole protocol: SETUP, requests, subgroup and fetch streams, varints.
  Not implemented: see "Not done" above. Revision 23 (2 November 2026) exists and is not followed.
- [End-to-End Secure Objects for Media over QUIC Transport, draft-ietf-moq-secure-objects-01](https://datatracker.ietf.org/doc/html/draft-ietf-moq-secure-objects-01)
  (Internet-Draft, July 2026, expires 7 January 2027, still the current revision).
  Takes: the Kolo profile of package `secobj`, cipher suite 0x0004.
  Not implemented: interop with other implementations, other suites.
- [RFC 9605, Secure Frame (SFrame)](https://www.rfc-editor.org/info/rfc9605)
  (Proposed Standard, August 2024, updated by RFC 10079, November 2026).
  Takes: the cipher suite identifiers (section 8.1).
  Not implemented: the SFrame header format.
- [RFC 5869, HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/info/rfc5869)
  (Informational, May 2010).
  Takes: HKDF-SHA256 for the track keys.
- [RFC 3711, The Secure Real-time Transport Protocol (SRTP)](https://www.rfc-editor.org/info/rfc3711)
  (Proposed Standard, March 2004).
  Takes: the minimum 64-entry replay window (section 3.3.2).
  Not implemented: SRTP.
- [RFC 9846, The Transport Layer Security (TLS) Protocol Version 1.3](https://www.rfc-editor.org/info/rfc9846)
  (Proposed Standard, July 2026, obsoletes RFC 8446).
  Takes: the AEAD usage limit, rotation after 2^24 units (section 5.5).
