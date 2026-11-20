// Package kolomoq runs MoQ Transport (draft-ietf-moq-transport-22) sessions
// over authenticated Kolo connections: publish tracks of groups and
// objects, subscribe to them, fetch cached groups and relay tracks to many
// subscribers.
//
// Each control stream starts with the version preface "moqt-22"; objects
// travel only on subgroup and fetch streams, never in datagrams.
//
// Experimental: the API may change before v1.0.0.
package kolomoq
