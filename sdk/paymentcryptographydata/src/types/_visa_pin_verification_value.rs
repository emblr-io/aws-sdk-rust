// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that are required to generate or verify Visa PVV (PIN Verification Value).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct VisaPinVerificationValue {
    /// <p>The encrypted PIN block data to verify.</p>
    pub encrypted_pin_block: ::std::string::String,
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    pub pin_verification_key_index: i32,
}
impl VisaPinVerificationValue {
    /// <p>The encrypted PIN block data to verify.</p>
    pub fn encrypted_pin_block(&self) -> &str {
        use std::ops::Deref;
        self.encrypted_pin_block.deref()
    }
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    pub fn pin_verification_key_index(&self) -> i32 {
        self.pin_verification_key_index
    }
}
impl ::std::fmt::Debug for VisaPinVerificationValue {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VisaPinVerificationValue");
        formatter.field("encrypted_pin_block", &"*** Sensitive Data Redacted ***");
        formatter.field("pin_verification_key_index", &self.pin_verification_key_index);
        formatter.finish()
    }
}
impl VisaPinVerificationValue {
    /// Creates a new builder-style object to manufacture [`VisaPinVerificationValue`](crate::types::VisaPinVerificationValue).
    pub fn builder() -> crate::types::builders::VisaPinVerificationValueBuilder {
        crate::types::builders::VisaPinVerificationValueBuilder::default()
    }
}

/// A builder for [`VisaPinVerificationValue`](crate::types::VisaPinVerificationValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct VisaPinVerificationValueBuilder {
    pub(crate) encrypted_pin_block: ::std::option::Option<::std::string::String>,
    pub(crate) pin_verification_key_index: ::std::option::Option<i32>,
}
impl VisaPinVerificationValueBuilder {
    /// <p>The encrypted PIN block data to verify.</p>
    /// This field is required.
    pub fn encrypted_pin_block(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.encrypted_pin_block = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The encrypted PIN block data to verify.</p>
    pub fn set_encrypted_pin_block(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.encrypted_pin_block = input;
        self
    }
    /// <p>The encrypted PIN block data to verify.</p>
    pub fn get_encrypted_pin_block(&self) -> &::std::option::Option<::std::string::String> {
        &self.encrypted_pin_block
    }
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    /// This field is required.
    pub fn pin_verification_key_index(mut self, input: i32) -> Self {
        self.pin_verification_key_index = ::std::option::Option::Some(input);
        self
    }
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    pub fn set_pin_verification_key_index(mut self, input: ::std::option::Option<i32>) -> Self {
        self.pin_verification_key_index = input;
        self
    }
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    pub fn get_pin_verification_key_index(&self) -> &::std::option::Option<i32> {
        &self.pin_verification_key_index
    }
    /// Consumes the builder and constructs a [`VisaPinVerificationValue`](crate::types::VisaPinVerificationValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`encrypted_pin_block`](crate::types::builders::VisaPinVerificationValueBuilder::encrypted_pin_block)
    /// - [`pin_verification_key_index`](crate::types::builders::VisaPinVerificationValueBuilder::pin_verification_key_index)
    pub fn build(self) -> ::std::result::Result<crate::types::VisaPinVerificationValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VisaPinVerificationValue {
            encrypted_pin_block: self.encrypted_pin_block.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "encrypted_pin_block",
                    "encrypted_pin_block was not specified but it is required when building VisaPinVerificationValue",
                )
            })?,
            pin_verification_key_index: self.pin_verification_key_index.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pin_verification_key_index",
                    "pin_verification_key_index was not specified but it is required when building VisaPinVerificationValue",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for VisaPinVerificationValueBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VisaPinVerificationValueBuilder");
        formatter.field("encrypted_pin_block", &"*** Sensitive Data Redacted ***");
        formatter.field("pin_verification_key_index", &self.pin_verification_key_index);
        formatter.finish()
    }
}
