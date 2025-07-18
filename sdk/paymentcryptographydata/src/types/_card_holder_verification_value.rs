// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Card data parameters that are required to generate a cardholder verification value for the payment card.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CardHolderVerificationValue {
    /// <p>A random number generated by the issuer.</p>
    pub unpredictable_number: ::std::string::String,
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN).</p>
    pub pan_sequence_number: ::std::string::String,
    /// <p>The transaction counter value that comes from a point of sale terminal.</p>
    pub application_transaction_counter: ::std::string::String,
}
impl CardHolderVerificationValue {
    /// <p>A random number generated by the issuer.</p>
    pub fn unpredictable_number(&self) -> &str {
        use std::ops::Deref;
        self.unpredictable_number.deref()
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN).</p>
    pub fn pan_sequence_number(&self) -> &str {
        use std::ops::Deref;
        self.pan_sequence_number.deref()
    }
    /// <p>The transaction counter value that comes from a point of sale terminal.</p>
    pub fn application_transaction_counter(&self) -> &str {
        use std::ops::Deref;
        self.application_transaction_counter.deref()
    }
}
impl CardHolderVerificationValue {
    /// Creates a new builder-style object to manufacture [`CardHolderVerificationValue`](crate::types::CardHolderVerificationValue).
    pub fn builder() -> crate::types::builders::CardHolderVerificationValueBuilder {
        crate::types::builders::CardHolderVerificationValueBuilder::default()
    }
}

/// A builder for [`CardHolderVerificationValue`](crate::types::CardHolderVerificationValue).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CardHolderVerificationValueBuilder {
    pub(crate) unpredictable_number: ::std::option::Option<::std::string::String>,
    pub(crate) pan_sequence_number: ::std::option::Option<::std::string::String>,
    pub(crate) application_transaction_counter: ::std::option::Option<::std::string::String>,
}
impl CardHolderVerificationValueBuilder {
    /// <p>A random number generated by the issuer.</p>
    /// This field is required.
    pub fn unpredictable_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unpredictable_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A random number generated by the issuer.</p>
    pub fn set_unpredictable_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unpredictable_number = input;
        self
    }
    /// <p>A random number generated by the issuer.</p>
    pub fn get_unpredictable_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.unpredictable_number
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN).</p>
    /// This field is required.
    pub fn pan_sequence_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pan_sequence_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN).</p>
    pub fn set_pan_sequence_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pan_sequence_number = input;
        self
    }
    /// <p>A number that identifies and differentiates payment cards with the same Primary Account Number (PAN).</p>
    pub fn get_pan_sequence_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.pan_sequence_number
    }
    /// <p>The transaction counter value that comes from a point of sale terminal.</p>
    /// This field is required.
    pub fn application_transaction_counter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_transaction_counter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction counter value that comes from a point of sale terminal.</p>
    pub fn set_application_transaction_counter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_transaction_counter = input;
        self
    }
    /// <p>The transaction counter value that comes from a point of sale terminal.</p>
    pub fn get_application_transaction_counter(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_transaction_counter
    }
    /// Consumes the builder and constructs a [`CardHolderVerificationValue`](crate::types::CardHolderVerificationValue).
    /// This method will fail if any of the following fields are not set:
    /// - [`unpredictable_number`](crate::types::builders::CardHolderVerificationValueBuilder::unpredictable_number)
    /// - [`pan_sequence_number`](crate::types::builders::CardHolderVerificationValueBuilder::pan_sequence_number)
    /// - [`application_transaction_counter`](crate::types::builders::CardHolderVerificationValueBuilder::application_transaction_counter)
    pub fn build(self) -> ::std::result::Result<crate::types::CardHolderVerificationValue, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CardHolderVerificationValue {
            unpredictable_number: self.unpredictable_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unpredictable_number",
                    "unpredictable_number was not specified but it is required when building CardHolderVerificationValue",
                )
            })?,
            pan_sequence_number: self.pan_sequence_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "pan_sequence_number",
                    "pan_sequence_number was not specified but it is required when building CardHolderVerificationValue",
                )
            })?,
            application_transaction_counter: self.application_transaction_counter.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_transaction_counter",
                    "application_transaction_counter was not specified but it is required when building CardHolderVerificationValue",
                )
            })?,
        })
    }
}
