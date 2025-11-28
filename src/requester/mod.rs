// Licensed under the Apache-2.0 license

/// # Flows
///
/// The SPDM specification defines a set of valid flows and states that a requester can be in.
/// The specification for that can be found at [DSP0274].
/// This module models these states and the transitions in a fail-safe way,
/// guaranteeting the validity at any given time.
///
/// The state machines tracks the negotiated state of the remote responder.
/// We differntiate the protocol in 3 phases, resulting in 3 state machines:
///
/// ## VCA Stage
/// [VCASMContext]
///
/// ## Post-VCA Stage
/// [PostVCASMContext]
///
/// ## Post-Challenge
/// [[PostChallengeSMContext]]
pub mod flows;

pub mod requester_client;
