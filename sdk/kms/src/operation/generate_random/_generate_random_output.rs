// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct GenerateRandomOutput {
    /// <p>The random byte string. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub plaintext: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>The plaintext random bytes encrypted with the public key from the Nitro enclave. This ciphertext can be decrypted only by using a private key in the Nitro enclave.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub ciphertext_for_recipient: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl GenerateRandomOutput {
    /// <p>The random byte string. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn plaintext(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.plaintext.as_ref()
    }
    /// <p>The plaintext random bytes encrypted with the public key from the Nitro enclave. This ciphertext can be decrypted only by using a private key in the Nitro enclave.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn ciphertext_for_recipient(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.ciphertext_for_recipient.as_ref()
    }
}
impl ::std::fmt::Debug for GenerateRandomOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GenerateRandomOutput");
        formatter.field("plaintext", &"*** Sensitive Data Redacted ***");
        formatter.field("ciphertext_for_recipient", &self.ciphertext_for_recipient);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for GenerateRandomOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GenerateRandomOutput {
    /// Creates a new builder-style object to manufacture [`GenerateRandomOutput`](crate::operation::generate_random::GenerateRandomOutput).
    pub fn builder() -> crate::operation::generate_random::builders::GenerateRandomOutputBuilder {
        crate::operation::generate_random::builders::GenerateRandomOutputBuilder::default()
    }
}

/// A builder for [`GenerateRandomOutput`](crate::operation::generate_random::GenerateRandomOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct GenerateRandomOutputBuilder {
    pub(crate) plaintext: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) ciphertext_for_recipient: ::std::option::Option<::aws_smithy_types::Blob>,
    _request_id: Option<String>,
}
impl GenerateRandomOutputBuilder {
    /// <p>The random byte string. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn plaintext(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.plaintext = ::std::option::Option::Some(input);
        self
    }
    /// <p>The random byte string. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn set_plaintext(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.plaintext = input;
        self
    }
    /// <p>The random byte string. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn get_plaintext(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.plaintext
    }
    /// <p>The plaintext random bytes encrypted with the public key from the Nitro enclave. This ciphertext can be decrypted only by using a private key in the Nitro enclave.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn ciphertext_for_recipient(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.ciphertext_for_recipient = ::std::option::Option::Some(input);
        self
    }
    /// <p>The plaintext random bytes encrypted with the public key from the Nitro enclave. This ciphertext can be decrypted only by using a private key in the Nitro enclave.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn set_ciphertext_for_recipient(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.ciphertext_for_recipient = input;
        self
    }
    /// <p>The plaintext random bytes encrypted with the public key from the Nitro enclave. This ciphertext can be decrypted only by using a private key in the Nitro enclave.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn get_ciphertext_for_recipient(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.ciphertext_for_recipient
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GenerateRandomOutput`](crate::operation::generate_random::GenerateRandomOutput).
    pub fn build(self) -> crate::operation::generate_random::GenerateRandomOutput {
        crate::operation::generate_random::GenerateRandomOutput {
            plaintext: self.plaintext,
            ciphertext_for_recipient: self.ciphertext_for_recipient,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for GenerateRandomOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("GenerateRandomOutputBuilder");
        formatter.field("plaintext", &"*** Sensitive Data Redacted ***");
        formatter.field("ciphertext_for_recipient", &self.ciphertext_for_recipient);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
