package attestation

import enclave "github.com/edgebitio/nitro-enclaves-sdk-go"

func MakeAttestation() ([]byte, error) {

	enclaveHandle, err := enclave.GetOrInitializeHandle()

	if err != nil {
		return nil, err
	}

	attestationDocument, err := enclaveHandle.Attest(enclave.AttestationOptions{})

	if err != nil {
		return nil, err
	}

	return attestationDocument, nil

}
