// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters to derive the confidentiality and integrity keys for a payment card using Amex derivation method.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct AmexAttributes {
    /// <p>The method to use when deriving the master key for a payment card using Amex derivation.</p>
    pub major_key_derivation_mode: crate::types::MajorKeyDerivationMode,
    /// <p>The Primary Account Number (PAN) of the cardholder.</p>
    pub primary_account_number: ::std::string::String,
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN). Typically 00 is used, if no value is provided by the terminal.</p>
    pub pan_sequence_number: ::std::string::String,
    /// <p>The transaction counter of the current transaction that is provided by the terminal during transaction processing.</p>
    pub application_transaction_counter: ::std::string::String,
    /// <p>The <code>keyArn</code> of the issuer master key for cryptogram (IMK-AC) for the payment card.</p>
    pub authorization_request_key_identifier: ::std::string::String,
    /// <p>The encrypted pinblock of the old pin stored on the chip card.</p>
    pub current_pin_attributes: ::std::option::Option<crate::types::CurrentPinAttributes>,
}
impl AmexAttributes {
    /// <p>The method to use when deriving the master key for a payment card using Amex derivation.</p>
    pub fn major_key_derivation_mode(&self) -> &crate::types::MajorKeyDerivationMode {
        &self.major_key_derivation_mode
    }
    /// <p>The Primary Account Number (PAN) of the cardholder.</p>
    pub fn primary_account_number(&self) -> &str {
        use std::ops::Deref;
        self.primary_account_number.deref()
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN). Typically 00 is used, if no value is provided by the terminal.</p>
    pub fn pan_sequence_number(&self) -> &str {
        use std::ops::Deref;
        self.pan_sequence_number.deref()
    }
    /// <p>The transaction counter of the current transaction that is provided by the terminal during transaction processing.</p>
    pub fn application_transaction_counter(&self) -> &str {
        use std::ops::Deref;
        self.application_transaction_counter.deref()
    }
    /// <p>The <code>keyArn</code> of the issuer master key for cryptogram (IMK-AC) for the payment card.</p>
    pub fn authorization_request_key_identifier(&self) -> &str {
        use std::ops::Deref;
        self.authorization_request_key_identifier.deref()
    }
    /// <p>The encrypted pinblock of the old pin stored on the chip card.</p>
    pub fn current_pin_attributes(&self) -> ::std::option::Option<&crate::types::CurrentPinAttributes> {
        self.current_pin_attributes.as_ref()
    }
}
impl ::std::fmt::Debug for AmexAttributes {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AmexAttributes");
        formatter.field("major_key_derivation_mode", &self.major_key_derivation_mode);
        formatter.field("primary_account_number", &"*** Sensitive Data Redacted ***");
        formatter.field("pan_sequence_number", &self.pan_sequence_number);
        formatter.field("application_transaction_counter", &self.application_transaction_counter);
        formatter.field("authorization_request_key_identifier", &self.authorization_request_key_identifier);
        formatter.field("current_pin_attributes", &self.current_pin_attributes);
        formatter.finish()
    }
}
impl AmexAttributes {
    /// Creates a new builder-style object to manufacture [`AmexAttributes`](crate::types::AmexAttributes).
    pub fn builder() -> crate::types::builders::AmexAttributesBuilder {
        crate::types::builders::AmexAttributesBuilder::default()
    }
}

/// A builder for [`AmexAttributes`](crate::types::AmexAttributes).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct AmexAttributesBuilder {
    pub(crate) major_key_derivation_mode: ::std::option::Option<crate::types::MajorKeyDerivationMode>,
    pub(crate) primary_account_number: ::std::option::Option<::std::string::String>,
    pub(crate) pan_sequence_number: ::std::option::Option<::std::string::String>,
    pub(crate) application_transaction_counter: ::std::option::Option<::std::string::String>,
    pub(crate) authorization_request_key_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) current_pin_attributes: ::std::option::Option<crate::types::CurrentPinAttributes>,
}
impl AmexAttributesBuilder {
    /// <p>The method to use when deriving the master key for a payment card using Amex derivation.</p>
    /// This field is required.
    pub fn major_key_derivation_mode(mut self, input: crate::types::MajorKeyDerivationMode) -> Self {
        self.major_key_derivation_mode = ::std::option::Option::Some(input);
        self
    }
    /// <p>The method to use when deriving the master key for a payment card using Amex derivation.</p>
    pub fn set_major_key_derivation_mode(mut self, input: ::std::option::Option<crate::types::MajorKeyDerivationMode>) -> Self {
        self.major_key_derivation_mode = input;
        self
    }
    /// <p>The method to use when deriving the master key for a payment card using Amex derivation.</p>
    pub fn get_major_key_derivation_mode(&self) -> &::std::option::Option<crate::types::MajorKeyDerivationMode> {
        &self.major_key_derivation_mode
    }
    /// <p>The Primary Account Number (PAN) of the cardholder.</p>
    /// This field is required.
    pub fn primary_account_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.primary_account_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Primary Account Number (PAN) of the cardholder.</p>
    pub fn set_primary_account_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.primary_account_number = input;
        self
    }
    /// <p>The Primary Account Number (PAN) of the cardholder.</p>
    pub fn get_primary_account_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.primary_account_number
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN). Typically 00 is used, if no value is provided by the terminal.</p>
    /// This field is required.
    pub fn pan_sequence_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pan_sequence_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN). Typically 00 is used, if no value is provided by the terminal.</p>
    pub fn set_pan_sequence_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pan_sequence_number = input;
        self
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN). Typically 00 is used, if no value is provided by the terminal.</p>
    pub fn get_pan_sequence_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.pan_sequence_number
    }
    /// <p>The transaction counter of the current transaction that is provided by the terminal during transaction processing.</p>
    /// This field is required.
    pub fn application_transaction_counter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_transaction_counter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction counter of the current transaction that is provided by the terminal during transaction processing.</p>
    pub fn set_application_transaction_counter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_transaction_counter = input;
        self
    }
    /// <p>The transaction counter of the current transaction that is provided by the terminal during transaction processing.</p>
    pub fn get_application_transaction_counter(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_transaction_counter
    }
    /// <p>The <code>keyArn</code> of the issuer master key for cryptogram (IMK-AC) for the payment card.</p>
    /// This field is required.
    pub fn authorization_request_key_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.authorization_request_key_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>keyArn</code> of the issuer master key for cryptogram (IMK-AC) for the payment card.</p>
    pub fn set_authorization_request_key_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.authorization_request_key_identifier = input;
        self
    }
    /// <p>The <code>keyArn</code> of the issuer master key for cryptogram (IMK-AC) for the payment card.</p>
    pub fn get_authorization_request_key_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.authorization_request_key_identifier
    }
    /// <p>The encrypted pinblock of the old pin stored on the chip card.</p>
    pub fn current_pin_attributes(mut self, input: crate::types::CurrentPinAttributes) -> Self {
        self.current_pin_attributes = ::std::option::Option::Some(input);
        self
    }
    /// <p>The encrypted pinblock of the old pin stored on the chip card.</p>
    pub fn set_current_pin_attributes(mut self, input: ::std::option::Option<crate::types::CurrentPinAttributes>) -> Self {
        self.current_pin_attributes = input;
        self
    }
    /// <p>The encrypted pinblock of the old pin stored on the chip card.</p>
    pub fn get_current_pin_attributes(&self) -> &::std::option::Option<crate::types::CurrentPinAttributes> {
        &self.current_pin_attributes
    }
    /// Consumes the builder and constructs a [`AmexAttributes`](crate::types::AmexAttributes).
    /// This method will fail if any of the following fields are not set:
    /// - [`major_key_derivation_mode`](crate::types::builders::AmexAttributesBuilder::major_key_derivation_mode)
    /// - [`primary_account_number`](crate::types::builders::AmexAttributesBuilder::primary_account_number)
    /// - [`pan_sequence_number`](crate::types::builders::AmexAttributesBuilder::pan_sequence_number)
    /// - [`application_transaction_counter`](crate::types::builders::AmexAttributesBuilder::application_transaction_counter)
    /// - [`authorization_request_key_identifier`](crate::types::builders::AmexAttributesBuilder::authorization_request_key_identifier)
    pub fn build(self) -> ::std::result::Result<crate::types::AmexAttributes, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AmexAttributes {
            major_key_derivation_mode: self.major_key_derivation_mode.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "major_key_derivation_mode",
                    "major_key_derivation_mode was not specified but it is required when building AmexAttributes",
                )
            })?,
            primary_account_number: self.primary_account_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "primary_account_number",
                    "primary_account_number was not specified but it is required when building AmexAttributes",
                )
            })?,
            pan_sequence_number: self.pan_sequence_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pan_sequence_number",
                    "pan_sequence_number was not specified but it is required when building AmexAttributes",
                )
            })?,
            application_transaction_counter: self.application_transaction_counter.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_transaction_counter",
                    "application_transaction_counter was not specified but it is required when building AmexAttributes",
                )
            })?,
            authorization_request_key_identifier: self.authorization_request_key_identifier.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "authorization_request_key_identifier",
                    "authorization_request_key_identifier was not specified but it is required when building AmexAttributes",
                )
            })?,
            current_pin_attributes: self.current_pin_attributes,
        })
    }
}
impl ::std::fmt::Debug for AmexAttributesBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("AmexAttributesBuilder");
        formatter.field("major_key_derivation_mode", &self.major_key_derivation_mode);
        formatter.field("primary_account_number", &"*** Sensitive Data Redacted ***");
        formatter.field("pan_sequence_number", &self.pan_sequence_number);
        formatter.field("application_transaction_counter", &self.application_transaction_counter);
        formatter.field("authorization_request_key_identifier", &self.authorization_request_key_identifier);
        formatter.field("current_pin_attributes", &self.current_pin_attributes);
        formatter.finish()
    }
}
