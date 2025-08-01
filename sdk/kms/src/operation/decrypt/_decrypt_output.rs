// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DecryptOutput {
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN">key ARN</a>) of the KMS key that was used to decrypt the ciphertext.</p>
    pub key_id: ::std::option::Option<::std::string::String>,
    /// <p>Decrypted plaintext data. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub plaintext: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>The encryption algorithm that was used to decrypt the ciphertext.</p>
    pub encryption_algorithm: ::std::option::Option<crate::types::EncryptionAlgorithmSpec>,
    /// <p>The plaintext data encrypted with the public key in the attestation document.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub ciphertext_for_recipient: ::std::option::Option<::aws_smithy_types::Blob>,
    /// <p>The identifier of the key material used to decrypt the ciphertext. This field is present only when the operation uses a symmetric encryption KMS key. This field is omitted if the request includes the <code>Recipient</code> parameter.</p>
    pub key_material_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DecryptOutput {
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN">key ARN</a>) of the KMS key that was used to decrypt the ciphertext.</p>
    pub fn key_id(&self) -> ::std::option::Option<&str> {
        self.key_id.as_deref()
    }
    /// <p>Decrypted plaintext data. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn plaintext(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.plaintext.as_ref()
    }
    /// <p>The encryption algorithm that was used to decrypt the ciphertext.</p>
    pub fn encryption_algorithm(&self) -> ::std::option::Option<&crate::types::EncryptionAlgorithmSpec> {
        self.encryption_algorithm.as_ref()
    }
    /// <p>The plaintext data encrypted with the public key in the attestation document.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn ciphertext_for_recipient(&self) -> ::std::option::Option<&::aws_smithy_types::Blob> {
        self.ciphertext_for_recipient.as_ref()
    }
    /// <p>The identifier of the key material used to decrypt the ciphertext. This field is present only when the operation uses a symmetric encryption KMS key. This field is omitted if the request includes the <code>Recipient</code> parameter.</p>
    pub fn key_material_id(&self) -> ::std::option::Option<&str> {
        self.key_material_id.as_deref()
    }
}
impl ::std::fmt::Debug for DecryptOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DecryptOutput");
        formatter.field("key_id", &self.key_id);
        formatter.field("plaintext", &"*** Sensitive Data Redacted ***");
        formatter.field("encryption_algorithm", &self.encryption_algorithm);
        formatter.field("ciphertext_for_recipient", &self.ciphertext_for_recipient);
        formatter.field("key_material_id", &self.key_material_id);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for DecryptOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DecryptOutput {
    /// Creates a new builder-style object to manufacture [`DecryptOutput`](crate::operation::decrypt::DecryptOutput).
    pub fn builder() -> crate::operation::decrypt::builders::DecryptOutputBuilder {
        crate::operation::decrypt::builders::DecryptOutputBuilder::default()
    }
}

/// A builder for [`DecryptOutput`](crate::operation::decrypt::DecryptOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DecryptOutputBuilder {
    pub(crate) key_id: ::std::option::Option<::std::string::String>,
    pub(crate) plaintext: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) encryption_algorithm: ::std::option::Option<crate::types::EncryptionAlgorithmSpec>,
    pub(crate) ciphertext_for_recipient: ::std::option::Option<::aws_smithy_types::Blob>,
    pub(crate) key_material_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DecryptOutputBuilder {
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN">key ARN</a>) of the KMS key that was used to decrypt the ciphertext.</p>
    pub fn key_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN">key ARN</a>) of the KMS key that was used to decrypt the ciphertext.</p>
    pub fn set_key_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_id = input;
        self
    }
    /// <p>The Amazon Resource Name (<a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-id-key-ARN">key ARN</a>) of the KMS key that was used to decrypt the ciphertext.</p>
    pub fn get_key_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_id
    }
    /// <p>Decrypted plaintext data. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn plaintext(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.plaintext = ::std::option::Option::Some(input);
        self
    }
    /// <p>Decrypted plaintext data. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn set_plaintext(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.plaintext = input;
        self
    }
    /// <p>Decrypted plaintext data. When you use the HTTP API or the Amazon Web Services CLI, the value is Base64-encoded. Otherwise, it is not Base64-encoded.</p>
    /// <p>If the response includes the <code>CiphertextForRecipient</code> field, the <code>Plaintext</code> field is null or empty.</p>
    pub fn get_plaintext(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.plaintext
    }
    /// <p>The encryption algorithm that was used to decrypt the ciphertext.</p>
    pub fn encryption_algorithm(mut self, input: crate::types::EncryptionAlgorithmSpec) -> Self {
        self.encryption_algorithm = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encryption algorithm that was used to decrypt the ciphertext.</p>
    pub fn set_encryption_algorithm(mut self, input: ::std::option::Option<crate::types::EncryptionAlgorithmSpec>) -> Self {
        self.encryption_algorithm = input;
        self
    }
    /// <p>The encryption algorithm that was used to decrypt the ciphertext.</p>
    pub fn get_encryption_algorithm(&self) -> &::std::option::Option<crate::types::EncryptionAlgorithmSpec> {
        &self.encryption_algorithm
    }
    /// <p>The plaintext data encrypted with the public key in the attestation document.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn ciphertext_for_recipient(mut self, input: ::aws_smithy_types::Blob) -> Self {
        self.ciphertext_for_recipient = ::std::option::Option::Some(input);
        self
    }
    /// <p>The plaintext data encrypted with the public key in the attestation document.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn set_ciphertext_for_recipient(mut self, input: ::std::option::Option<::aws_smithy_types::Blob>) -> Self {
        self.ciphertext_for_recipient = input;
        self
    }
    /// <p>The plaintext data encrypted with the public key in the attestation document.</p>
    /// <p>This field is included in the response only when the <code>Recipient</code> parameter in the request includes a valid attestation document from an Amazon Web Services Nitro enclave. For information about the interaction between KMS and Amazon Web Services Nitro Enclaves, see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/services-nitro-enclaves.html">How Amazon Web Services Nitro Enclaves uses KMS</a> in the <i>Key Management Service Developer Guide</i>.</p>
    pub fn get_ciphertext_for_recipient(&self) -> &::std::option::Option<::aws_smithy_types::Blob> {
        &self.ciphertext_for_recipient
    }
    /// <p>The identifier of the key material used to decrypt the ciphertext. This field is present only when the operation uses a symmetric encryption KMS key. This field is omitted if the request includes the <code>Recipient</code> parameter.</p>
    pub fn key_material_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_material_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the key material used to decrypt the ciphertext. This field is present only when the operation uses a symmetric encryption KMS key. This field is omitted if the request includes the <code>Recipient</code> parameter.</p>
    pub fn set_key_material_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_material_id = input;
        self
    }
    /// <p>The identifier of the key material used to decrypt the ciphertext. This field is present only when the operation uses a symmetric encryption KMS key. This field is omitted if the request includes the <code>Recipient</code> parameter.</p>
    pub fn get_key_material_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_material_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DecryptOutput`](crate::operation::decrypt::DecryptOutput).
    pub fn build(self) -> crate::operation::decrypt::DecryptOutput {
        crate::operation::decrypt::DecryptOutput {
            key_id: self.key_id,
            plaintext: self.plaintext,
            encryption_algorithm: self.encryption_algorithm,
            ciphertext_for_recipient: self.ciphertext_for_recipient,
            key_material_id: self.key_material_id,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for DecryptOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DecryptOutputBuilder");
        formatter.field("key_id", &self.key_id);
        formatter.field("plaintext", &"*** Sensitive Data Redacted ***");
        formatter.field("encryption_algorithm", &self.encryption_algorithm);
        formatter.field("ciphertext_for_recipient", &self.ciphertext_for_recipient);
        formatter.field("key_material_id", &self.key_material_id);
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
