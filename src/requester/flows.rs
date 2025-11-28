// Licensed under the Apache-2.0 license

use smlang::statemachine;

statemachine! {
    name: Spdm,
    derive_states: [Debug],
    derive_events: [Clone, Debug],
    transitions: {
        /* VCA */
        *NotStarted + GetVersionResp / validate_version = VersionReceived, // GET_VERSION response received and validated
        VersionReceived + GetCapabilitiesResp / validate_caps = CapabilitiesReceived, // GET_CAPABILITIES response received and validated
        CapabilitiesReceived + NegotiateAlgorithmsResp / validate_algos = AlgorithmsNegotiated, // NEGOTIATE_ALGORITHMS response received and validated
        _ + GetVersionReq = NotStarted, //GET_VERSION request issued (session restart), valid for both VCA and Post-VCA

        /* Post-VCA */
        AlgorithmsNegotiated | DigestReceived + GetDigestResp / validate_digest = DigestReceived, // DIGESTS response received and validated
        AlgorithmsNegotiated + GetCertificateResp / validate_certificate = CertificateReceived, // CERTIFICATE response received and validated
        AlgorithmsNegotiated + ChallengeResp / validate_challenge = Challengd, // CHALLENGE response received and validated

        DigestReceived + GetCertificateResp / validate_certificate = CertificateReceived, // CERTIFICATE response received and validated
        DigestReceived + ChallengeResp / validate_challenge = Challengd, // CHALLENGE response received and validated
        // DigestReceived + DigestResp= AlgorithmsNegotiated, // DIGESTS request issued (session restart)

        CertificateReceived + GetCertificateResp / validate_certificate = CertificateReceived, // CERTIFICATE response received and validated (different slot)
        CertificateReceived + GetDigestResp / validate_digest = DigestReceived, // DIGESTS response received and validated (session restart)
        CertificateReceived + ChallengeResp / validate_challenge = Challengd, // CHALLENGE response received and validated

        _ + GetVersionResp = AlgorithmsNegotiated, // GET_VERSION response received (session restart)\

        /* Post-Challenge */
        Challenged + GetMeasurementResp = Challenged,
        // _ + _ = NotStarted, // Any + Any = NotStarted => kill flow and go back to NotStarted
    }
}

#[derive(Debug)]
pub struct SpdmContext;

impl SpdmStateMachineContext for SpdmContext {
    #[allow(missing_docs)]
    #[allow(clippy::unused_unit)]
    fn validate_version(&mut self) -> Result<(), ()> {
        Ok(())
    }

    #[allow(missing_docs)]
    #[allow(clippy::unused_unit)]
    fn validate_algos(&mut self) -> Result<(), ()> {
        Ok(())
    }

    #[allow(missing_docs)]
    #[allow(clippy::unused_unit)]
    fn validate_caps(&mut self) -> Result<(), ()> {
        Ok(())
    }

    #[allow(missing_docs)]
    #[allow(clippy::unused_unit)]
    fn validate_challenge(&mut self) -> Result<(), ()> {
        Ok(())
    }

    #[allow(missing_docs)]
    #[allow(clippy::unused_unit)]
    fn validate_certificate(&mut self) -> Result<(), ()> {
        Ok(())
    }

    #[allow(missing_docs)]
    #[allow(clippy::unused_unit)]
    fn validate_digest(&mut self) -> Result<(), ()> {
        Ok(())
    }
}
