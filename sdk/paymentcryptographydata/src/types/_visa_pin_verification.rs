// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that are required to generate or verify Visa PIN.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct VisaPinVerification {
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    pub pin_verification_key_index: i32,
    /// <p>Parameters that are required to generate or verify Visa PVV (PIN Verification Value).</p>
    pub verification_value: ::std::string::String,
}
impl VisaPinVerification {
    /// <p>The value for PIN verification index. It is used in the Visa PIN algorithm to calculate the PVV (PIN Verification Value).</p>
    pub fn pin_verification_key_index(&self) -> i32 {
        self.pin_verification_key_index
    }
    /// <p>Parameters that are required to generate or verify Visa PVV (PIN Verification Value).</p>
    pub fn verification_value(&self) -> &str {
        use std::ops::Deref;
        self.verification_value.deref()
    }
}
impl ::std::fmt::Debug for VisaPinVerification {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VisaPinVerification");
        formatter.field("pin_verification_key_index", &self.pin_verification_key_index);
        formatter.field("verification_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
impl VisaPinVerification {
    /// Creates a new builder-style object to manufacture [`VisaPinVerification`](crate::types::VisaPinVerification).
    pub fn builder() -> crate::types::builders::VisaPinVerificationBuilder {
        crate::types::builders::VisaPinVerificationBuilder::default()
    }
}

/// A builder for [`VisaPinVerification`](crate::types::VisaPinVerification).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct VisaPinVerificationBuilder {
    pub(crate) pin_verification_key_index: ::std::option::Option<i32>,
    pub(crate) verification_value: ::std::option::Option<::std::string::String>,
}
impl VisaPinVerificationBuilder {
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
    /// <p>Parameters that are required to generate or verify Visa PVV (PIN Verification Value).</p>
    /// This field is required.
    pub fn verification_value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.verification_value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Parameters that are required to generate or verify Visa PVV (PIN Verification Value).</p>
    pub fn set_verification_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.verification_value = input;
        self
    }
    /// <p>Parameters that are required to generate or verify Visa PVV (PIN Verification Value).</p>
    pub fn get_verification_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.verification_value
    }
    /// Consumes the builder and constructs a [`VisaPinVerification`](crate::types::VisaPinVerification).
    /// This method will fail if any of the following fields are not set:
    /// - [`pin_verification_key_index`](crate::types::builders::VisaPinVerificationBuilder::pin_verification_key_index)
    /// - [`verification_value`](crate::types::builders::VisaPinVerificationBuilder::verification_value)
    pub fn build(self) -> ::std::result::Result<crate::types::VisaPinVerification, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::VisaPinVerification {
            pin_verification_key_index: self.pin_verification_key_index.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pin_verification_key_index",
                    "pin_verification_key_index was not specified but it is required when building VisaPinVerification",
                )
            })?,
            verification_value: self.verification_value.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "verification_value",
                    "verification_value was not specified but it is required when building VisaPinVerification",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for VisaPinVerificationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("VisaPinVerificationBuilder");
        formatter.field("pin_verification_key_index", &self.pin_verification_key_index);
        formatter.field("verification_value", &"*** Sensitive Data Redacted ***");
        formatter.finish()
    }
}
