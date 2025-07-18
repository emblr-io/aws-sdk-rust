// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct VerifyAuthRequestCryptogramInput {
    /// <p>The <code>keyARN</code> of the major encryption key that Amazon Web Services Payment Cryptography uses for ARQC verification.</p>
    pub key_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The transaction data that Amazon Web Services Payment Cryptography uses for ARQC verification. The same transaction is used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub transaction_data: ::std::option::Option<::std::string::String>,
    /// <p>The auth request cryptogram imported into Amazon Web Services Payment Cryptography for ARQC verification using a major encryption key and transaction data.</p>
    pub auth_request_cryptogram: ::std::option::Option<::std::string::String>,
    /// <p>The method to use when deriving the major encryption key for ARQC verification within Amazon Web Services Payment Cryptography. The same key derivation mode was used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub major_key_derivation_mode: ::std::option::Option<crate::types::MajorKeyDerivationMode>,
    /// <p>The attributes and values to use for deriving a session key for ARQC verification within Amazon Web Services Payment Cryptography. The same attributes were used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub session_key_derivation_attributes: ::std::option::Option<crate::types::SessionKeyDerivation>,
    /// <p>The attributes and values for auth request cryptogram verification. These parameters are required in case using ARPC Method 1 or Method 2 for ARQC verification.</p>
    pub auth_response_attributes: ::std::option::Option<crate::types::CryptogramAuthResponse>,
}
impl VerifyAuthRequestCryptogramInput {
    /// <p>The <code>keyARN</code> of the major encryption key that Amazon Web Services Payment Cryptography uses for ARQC verification.</p>
    pub fn key_identifier(&self) -> ::std::option::Option<&str> {
        self.key_identifier.as_deref()
    }
    /// <p>The transaction data that Amazon Web Services Payment Cryptography uses for ARQC verification. The same transaction is used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn transaction_data(&self) -> ::std::option::Option<&str> {
        self.transaction_data.as_deref()
    }
    /// <p>The auth request cryptogram imported into Amazon Web Services Payment Cryptography for ARQC verification using a major encryption key and transaction data.</p>
    pub fn auth_request_cryptogram(&self) -> ::std::option::Option<&str> {
        self.auth_request_cryptogram.as_deref()
    }
    /// <p>The method to use when deriving the major encryption key for ARQC verification within Amazon Web Services Payment Cryptography. The same key derivation mode was used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn major_key_derivation_mode(&self) -> ::std::option::Option<&crate::types::MajorKeyDerivationMode> {
        self.major_key_derivation_mode.as_ref()
    }
    /// <p>The attributes and values to use for deriving a session key for ARQC verification within Amazon Web Services Payment Cryptography. The same attributes were used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn session_key_derivation_attributes(&self) -> ::std::option::Option<&crate::types::SessionKeyDerivation> {
        self.session_key_derivation_attributes.as_ref()
    }
    /// <p>The attributes and values for auth request cryptogram verification. These parameters are required in case using ARPC Method 1 or Method 2 for ARQC verification.</p>
    pub fn auth_response_attributes(&self) -> ::std::option::Option<&crate::types::CryptogramAuthResponse> {
        self.auth_response_attributes.as_ref()
    }
}
impl ::std::fmt::Debug for VerifyAuthRequestCryptogramInput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VerifyAuthRequestCryptogramInput");
        formatter.field("key_identifier", &self.key_identifier);
        formatter.field("transaction_data", &"*** Sensitive Data Redacted ***");
        formatter.field("auth_request_cryptogram", &"*** Sensitive Data Redacted ***");
        formatter.field("major_key_derivation_mode", &self.major_key_derivation_mode);
        formatter.field("session_key_derivation_attributes", &self.session_key_derivation_attributes);
        formatter.field("auth_response_attributes", &self.auth_response_attributes);
        formatter.finish()
    }
}
impl VerifyAuthRequestCryptogramInput {
    /// Creates a new builder-style object to manufacture [`VerifyAuthRequestCryptogramInput`](crate::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramInput).
    pub fn builder() -> crate::operation::verify_auth_request_cryptogram::builders::VerifyAuthRequestCryptogramInputBuilder {
        crate::operation::verify_auth_request_cryptogram::builders::VerifyAuthRequestCryptogramInputBuilder::default()
    }
}

/// A builder for [`VerifyAuthRequestCryptogramInput`](crate::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct VerifyAuthRequestCryptogramInputBuilder {
    pub(crate) key_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) transaction_data: ::std::option::Option<::std::string::String>,
    pub(crate) auth_request_cryptogram: ::std::option::Option<::std::string::String>,
    pub(crate) major_key_derivation_mode: ::std::option::Option<crate::types::MajorKeyDerivationMode>,
    pub(crate) session_key_derivation_attributes: ::std::option::Option<crate::types::SessionKeyDerivation>,
    pub(crate) auth_response_attributes: ::std::option::Option<crate::types::CryptogramAuthResponse>,
}
impl VerifyAuthRequestCryptogramInputBuilder {
    /// <p>The <code>keyARN</code> of the major encryption key that Amazon Web Services Payment Cryptography uses for ARQC verification.</p>
    /// This field is required.
    pub fn key_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>keyARN</code> of the major encryption key that Amazon Web Services Payment Cryptography uses for ARQC verification.</p>
    pub fn set_key_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key_identifier = input;
        self
    }
    /// <p>The <code>keyARN</code> of the major encryption key that Amazon Web Services Payment Cryptography uses for ARQC verification.</p>
    pub fn get_key_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.key_identifier
    }
    /// <p>The transaction data that Amazon Web Services Payment Cryptography uses for ARQC verification. The same transaction is used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    /// This field is required.
    pub fn transaction_data(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.transaction_data = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction data that Amazon Web Services Payment Cryptography uses for ARQC verification. The same transaction is used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn set_transaction_data(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.transaction_data = input;
        self
    }
    /// <p>The transaction data that Amazon Web Services Payment Cryptography uses for ARQC verification. The same transaction is used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn get_transaction_data(&self) -> &::std::option::Option<::std::string::String> {
        &self.transaction_data
    }
    /// <p>The auth request cryptogram imported into Amazon Web Services Payment Cryptography for ARQC verification using a major encryption key and transaction data.</p>
    /// This field is required.
    pub fn auth_request_cryptogram(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.auth_request_cryptogram = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The auth request cryptogram imported into Amazon Web Services Payment Cryptography for ARQC verification using a major encryption key and transaction data.</p>
    pub fn set_auth_request_cryptogram(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.auth_request_cryptogram = input;
        self
    }
    /// <p>The auth request cryptogram imported into Amazon Web Services Payment Cryptography for ARQC verification using a major encryption key and transaction data.</p>
    pub fn get_auth_request_cryptogram(&self) -> &::std::option::Option<::std::string::String> {
        &self.auth_request_cryptogram
    }
    /// <p>The method to use when deriving the major encryption key for ARQC verification within Amazon Web Services Payment Cryptography. The same key derivation mode was used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    /// This field is required.
    pub fn major_key_derivation_mode(mut self, input: crate::types::MajorKeyDerivationMode) -> Self {
        self.major_key_derivation_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The method to use when deriving the major encryption key for ARQC verification within Amazon Web Services Payment Cryptography. The same key derivation mode was used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn set_major_key_derivation_mode(mut self, input: ::std::option::Option<crate::types::MajorKeyDerivationMode>) -> Self {
        self.major_key_derivation_mode = input;
        self
    }
    /// <p>The method to use when deriving the major encryption key for ARQC verification within Amazon Web Services Payment Cryptography. The same key derivation mode was used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn get_major_key_derivation_mode(&self) -> &::std::option::Option<crate::types::MajorKeyDerivationMode> {
        &self.major_key_derivation_mode
    }
    /// <p>The attributes and values to use for deriving a session key for ARQC verification within Amazon Web Services Payment Cryptography. The same attributes were used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    /// This field is required.
    pub fn session_key_derivation_attributes(mut self, input: crate::types::SessionKeyDerivation) -> Self {
        self.session_key_derivation_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attributes and values to use for deriving a session key for ARQC verification within Amazon Web Services Payment Cryptography. The same attributes were used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn set_session_key_derivation_attributes(mut self, input: ::std::option::Option<crate::types::SessionKeyDerivation>) -> Self {
        self.session_key_derivation_attributes = input;
        self
    }
    /// <p>The attributes and values to use for deriving a session key for ARQC verification within Amazon Web Services Payment Cryptography. The same attributes were used for ARQC generation outside of Amazon Web Services Payment Cryptography.</p>
    pub fn get_session_key_derivation_attributes(&self) -> &::std::option::Option<crate::types::SessionKeyDerivation> {
        &self.session_key_derivation_attributes
    }
    /// <p>The attributes and values for auth request cryptogram verification. These parameters are required in case using ARPC Method 1 or Method 2 for ARQC verification.</p>
    pub fn auth_response_attributes(mut self, input: crate::types::CryptogramAuthResponse) -> Self {
        self.auth_response_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The attributes and values for auth request cryptogram verification. These parameters are required in case using ARPC Method 1 or Method 2 for ARQC verification.</p>
    pub fn set_auth_response_attributes(mut self, input: ::std::option::Option<crate::types::CryptogramAuthResponse>) -> Self {
        self.auth_response_attributes = input;
        self
    }
    /// <p>The attributes and values for auth request cryptogram verification. These parameters are required in case using ARPC Method 1 or Method 2 for ARQC verification.</p>
    pub fn get_auth_response_attributes(&self) -> &::std::option::Option<crate::types::CryptogramAuthResponse> {
        &self.auth_response_attributes
    }
    /// Consumes the builder and constructs a [`VerifyAuthRequestCryptogramInput`](crate::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::verify_auth_request_cryptogram::VerifyAuthRequestCryptogramInput {
            key_identifier: self.key_identifier,
            transaction_data: self.transaction_data,
            auth_request_cryptogram: self.auth_request_cryptogram,
            major_key_derivation_mode: self.major_key_derivation_mode,
            session_key_derivation_attributes: self.session_key_derivation_attributes,
            auth_response_attributes: self.auth_response_attributes,
        })
    }
}
impl ::std::fmt::Debug for VerifyAuthRequestCryptogramInputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VerifyAuthRequestCryptogramInputBuilder");
        formatter.field("key_identifier", &self.key_identifier);
        formatter.field("transaction_data", &"*** Sensitive Data Redacted ***");
        formatter.field("auth_request_cryptogram", &"*** Sensitive Data Redacted ***");
        formatter.field("major_key_derivation_mode", &self.major_key_derivation_mode);
        formatter.field("session_key_derivation_attributes", &self.session_key_derivation_attributes);
        formatter.field("auth_response_attributes", &self.auth_response_attributes);
        formatter.finish()
    }
}
