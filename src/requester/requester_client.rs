// Licensed under the Apache-2.0 license

use crate::context;
use crate::error::*;
use crate::protocol::version;
use crate::requester::flows::{SpdmContext, SpdmError, SpdmEvents, SpdmStateMachine, SpdmStates};

use crate::cert_store::*;
use crate::platform::evidence::SpdmEvidence;
use crate::platform::hash::SpdmHash;
use crate::platform::rng::SpdmRng;
use crate::platform::transport::SpdmTransport;
use crate::protocol::algorithms::*;
use crate::protocol::DeviceCapabilities;

pub struct Requester<'a> {
    pub responder_state: SpdmStateMachine<SpdmContext>,
    pub context_local: context::SpdmContext<'a>,
}

impl<'a> Requester<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        supported_versions: &'a [version::SpdmVersion],
        spdm_transport: &'a mut dyn SpdmTransport,
        local_capabilities: DeviceCapabilities,
        local_algorithms: LocalDeviceAlgorithms<'a>,
        device_certs_store: &'a mut dyn SpdmCertStore,
        hash: &'a mut dyn SpdmHash,
        m1: &'a mut dyn SpdmHash,
        l1: &'a mut dyn SpdmHash,
        rng: &'a mut dyn SpdmRng,
        evidence: &'a dyn SpdmEvidence,
    ) -> SpdmResult<Self> {
        let context_local = context::SpdmContext::new(
            supported_versions,
            spdm_transport,
            local_capabilities,
            local_algorithms,
            device_certs_store,
            hash,
            m1,
            l1,
            rng,
            evidence,
        )?;
        Ok(Requester {
            responder_state: SpdmStateMachine::new(SpdmContext),
            context_local,
        })
    }

    pub fn handle_event(&mut self, event: SpdmEvents) -> Result<&SpdmStates, SpdmError> {
        self.responder_state.process_event(event)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::cert_store::{CertStoreError, CertStoreResult, SpdmCertStore};
    use crate::codec::MessageBuf;
    use crate::platform::evidence::{SpdmEvidence, SpdmEvidenceResult};
    use crate::platform::hash::{SpdmHash, SpdmHashAlgoType, SpdmHashResult};
    use crate::platform::rng::{SpdmRng, SpdmRngResult};
    use crate::platform::transport::{SpdmTransport, TransportResult};
    use crate::protocol::algorithms::{
        AeadCipherSuite, AlgorithmPriorityTable, AsymAlgo, BaseAsymAlgo, BaseHashAlgo,
        DeviceAlgorithms, DheNamedGroup, KeySchedule, LocalDeviceAlgorithms, MeasurementHashAlgo,
        MeasurementSpecification, MelSpecification, OtherParamSupport, ReqBaseAsymAlg,
        ECC_P384_SIGNATURE_SIZE, SHA384_HASH_SIZE,
    };
    use crate::protocol::certs::{CertificateInfo, KeyUsageMask};

    struct MockSpdmTransportImpl {}

    impl SpdmTransport for MockSpdmTransportImpl {
        fn send_request<'a>(
            &mut self,
            _dest_eid: u8,
            _req: &mut MessageBuf<'a>,
        ) -> TransportResult<()> {
            Ok(())
        }

        fn receive_response<'a>(&mut self, _rsp: &mut MessageBuf<'a>) -> TransportResult<()> {
            Ok(())
        }

        fn receive_request<'a>(&mut self, _req: &mut MessageBuf<'a>) -> TransportResult<()> {
            Ok(())
        }

        fn send_response<'a>(&mut self, _resp: &mut MessageBuf<'a>) -> TransportResult<()> {
            Ok(())
        }

        fn max_message_size(&self) -> TransportResult<usize> {
            Ok(4096)
        }

        fn header_size(&self) -> usize {
            0
        }
    }

    struct MockSpdmCertStore {}

    impl SpdmCertStore for MockSpdmCertStore {
        fn slot_count(&self) -> u8 {
            0
        }

        fn is_provisioned(&self, _slot_id: u8) -> bool {
            false
        }

        fn cert_chain_len(&mut self, _asym_algo: AsymAlgo, _slot_id: u8) -> CertStoreResult<usize> {
            Err(CertStoreError::InvalidSlotId)
        }

        fn get_cert_chain<'a>(
            &mut self,
            _slot_id: u8,
            _asym_algo: AsymAlgo,
            _offset: usize,
            _cert_portion: &'a mut [u8],
        ) -> CertStoreResult<usize> {
            Err(CertStoreError::InvalidSlotId)
        }

        fn root_cert_hash<'a>(
            &mut self,
            _slot_id: u8,
            _asym_algo: AsymAlgo,
            _cert_hash: &'a mut [u8; SHA384_HASH_SIZE],
        ) -> CertStoreResult<()> {
            Err(CertStoreError::InvalidSlotId)
        }

        fn sign_hash<'a>(
            &self,
            _slot_id: u8,
            _hash: &'a [u8; SHA384_HASH_SIZE],
            _signature: &'a mut [u8; ECC_P384_SIGNATURE_SIZE],
        ) -> CertStoreResult<()> {
            Err(CertStoreError::InvalidSlotId)
        }

        fn key_pair_id(&self, _slot_id: u8) -> Option<u8> {
            None
        }

        fn cert_info(&self, _slot_id: u8) -> Option<CertificateInfo> {
            None
        }

        fn key_usage_mask(&self, _slot_id: u8) -> Option<KeyUsageMask> {
            None
        }
    }

    struct MockSpdmHash {
        algo: SpdmHashAlgoType,
    }

    impl SpdmHash for MockSpdmHash {
        fn hash(
            &mut self,
            _hash_algo: SpdmHashAlgoType,
            _data: &[u8],
            _hash: &mut [u8],
        ) -> SpdmHashResult<()> {
            Ok(())
        }

        fn init(
            &mut self,
            hash_algo: SpdmHashAlgoType,
            _data: Option<&[u8]>,
        ) -> SpdmHashResult<()> {
            self.algo = hash_algo;
            Ok(())
        }

        fn update(&mut self, _data: &[u8]) -> SpdmHashResult<()> {
            Ok(())
        }

        fn finalize(&mut self, _hash: &mut [u8]) -> SpdmHashResult<()> {
            Ok(())
        }

        fn reset(&mut self) {
            self.algo = SpdmHashAlgoType::SHA384;
        }

        fn algo(&self) -> SpdmHashAlgoType {
            self.algo
        }
    }

    struct MockSpdmRng {}

    impl SpdmRng for MockSpdmRng {
        fn get_random_bytes(&mut self, _buf: &mut [u8]) -> SpdmRngResult<()> {
            Ok(())
        }

        fn generate_random_number(&mut self, _random_number: &mut [u8]) -> SpdmRngResult<()> {
            Ok(())
        }
    }

    struct MockSpdmEvidence {}

    impl SpdmEvidence for MockSpdmEvidence {
        fn pcr_quote(&self, _buffer: &mut [u8], _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
            Ok(0)
        }

        fn pcr_quote_size(&self, _with_pqc_sig: bool) -> SpdmEvidenceResult<usize> {
            Ok(0)
        }
    }

    #[allow(static_mut_refs)]
    impl<'a> Default for Requester<'a> {
        /// Mock implementation for Requester::Default() to be used in simple flow tests.
        fn default() -> Self {
            static mut TRANSPORT: MockSpdmTransportImpl = MockSpdmTransportImpl {};
            static mut CERT_STORE: MockSpdmCertStore = MockSpdmCertStore {};
            static mut HASH: MockSpdmHash = MockSpdmHash {
                algo: SpdmHashAlgoType::SHA384,
            };
            static mut M1: MockSpdmHash = MockSpdmHash {
                algo: SpdmHashAlgoType::SHA384,
            };
            static mut L1: MockSpdmHash = MockSpdmHash {
                algo: SpdmHashAlgoType::SHA384,
            };
            static mut RNG: MockSpdmRng = MockSpdmRng {};
            static EVIDENCE: MockSpdmEvidence = MockSpdmEvidence {};
            static VERSIONS: [version::SpdmVersion; 4] = [
                version::SpdmVersion::V10,
                version::SpdmVersion::V11,
                version::SpdmVersion::V12,
                version::SpdmVersion::V13,
            ];

            let local_algorithms = LocalDeviceAlgorithms {
                device_algorithms: DeviceAlgorithms {
                    measurement_spec: MeasurementSpecification(0),
                    other_param_support: OtherParamSupport(0),
                    measurement_hash_algo: MeasurementHashAlgo(0),
                    base_asym_algo: BaseAsymAlgo(0),
                    base_hash_algo: BaseHashAlgo(0),
                    mel_specification: MelSpecification(0),
                    dhe_group: DheNamedGroup(0),
                    aead_cipher_suite: AeadCipherSuite(0),
                    req_base_asym_algo: ReqBaseAsymAlg(0),
                    key_schedule: KeySchedule(0),
                },
                algorithm_priority_table: AlgorithmPriorityTable {
                    measurement_specification: None,
                    opaque_data_format: None,
                    base_asym_algo: None,
                    base_hash_algo: None,
                    mel_specification: None,
                    dhe_group: None,
                    aead_cipher_suite: None,
                    req_base_asym_algo: None,
                    key_schedule: None,
                },
            };

            unsafe {
                Requester::new(
                    &VERSIONS,
                    &mut TRANSPORT,
                    DeviceCapabilities::default(),
                    local_algorithms,
                    &mut CERT_STORE,
                    &mut HASH,
                    &mut M1,
                    &mut L1,
                    &mut RNG,
                    &EVIDENCE,
                )
                .expect("Failed to create default Test Requester")
            }
        }
    }

    // TODO: how can we certainly achieve 100% coverage on state machines testing?
    #[test]
    fn test_requester_flow_vca_full() {
        let mut req_client = Requester::default();
        assert_eq!(req_client.responder_state.state(), &SpdmStates::NotStarted);

        let next_state = req_client.handle_event(SpdmEvents::GetVersionResp).unwrap();
        assert_eq!(next_state, &SpdmStates::VersionReceived);
        assert_eq!(
            req_client.responder_state.state(),
            &SpdmStates::VersionReceived
        );

        let next_state = req_client
            .handle_event(SpdmEvents::GetCapabilitiesResp)
            .unwrap();
        assert_eq!(next_state, &SpdmStates::CapabilitiesReceived);
        assert_eq!(
            req_client.responder_state.state(),
            &SpdmStates::CapabilitiesReceived
        );

        let next_state = req_client
            .handle_event(SpdmEvents::NegotiateAlgorithmsResp)
            .unwrap();
        assert_eq!(next_state, &SpdmStates::AlgorithmsNegotiated);
        assert_eq!(
            req_client.responder_state.state(),
            &SpdmStates::AlgorithmsNegotiated
        );

        // Test invalid events
        let next_state = req_client.handle_event(SpdmEvents::NegotiateAlgorithmsResp);
        assert_eq!(next_state, Err(SpdmError::InvalidEvent));
    }

    #[test]
    fn test_requester_flow_vca_early_abort() {
        let mut req_client = Requester::default();
        assert_eq!(req_client.responder_state.state(), &SpdmStates::NotStarted);

        let next_state = req_client.handle_event(SpdmEvents::GetVersionResp).unwrap();
        assert_eq!(next_state, &SpdmStates::VersionReceived);
        assert_eq!(
            req_client.responder_state.state(),
            &SpdmStates::VersionReceived
        );

        let next_state = req_client
            .handle_event(SpdmEvents::GetCapabilitiesResp)
            .unwrap();
        assert_eq!(next_state, &SpdmStates::CapabilitiesReceived);
        assert_eq!(
            req_client.responder_state.state(),
            &SpdmStates::CapabilitiesReceived
        );

        let broken_state = req_client.handle_event(SpdmEvents::GetVersionReq).unwrap();
        assert_eq!(broken_state, &SpdmStates::NotStarted);
        assert_eq!(req_client.responder_state.state(), &SpdmStates::NotStarted);
    }

    #[ignore]
    #[test]
    fn test_requester_flow_postvca_full() {
        todo!();
    }

    #[ignore]
    #[test]
    fn test_requester_flow_postvca_broken() {
        todo!();
    }
}
