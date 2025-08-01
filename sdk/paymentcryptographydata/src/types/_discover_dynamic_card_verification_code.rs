// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Parameters that are required to generate or verify dCVC (Dynamic Card Verification Code).</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct DiscoverDynamicCardVerificationCode {
    /// <p>The expiry date of a payment card.</p>
    pub card_expiry_date: ::std::string::String,
    /// <p>A random number that is generated by the issuer.</p>
    pub unpredictable_number: ::std::string::String,
    /// <p>The transaction counter value that comes from the terminal.</p>
    pub application_transaction_counter: ::std::string::String,
}
impl DiscoverDynamicCardVerificationCode {
    /// <p>The expiry date of a payment card.</p>
    pub fn card_expiry_date(&self) -> &str {
        use std::ops::Deref;
        self.card_expiry_date.deref()
    }
    /// <p>A random number that is generated by the issuer.</p>
    pub fn unpredictable_number(&self) -> &str {
        use std::ops::Deref;
        self.unpredictable_number.deref()
    }
    /// <p>The transaction counter value that comes from the terminal.</p>
    pub fn application_transaction_counter(&self) -> &str {
        use std::ops::Deref;
        self.application_transaction_counter.deref()
    }
}
impl ::std::fmt::Debug for DiscoverDynamicCardVerificationCode {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DiscoverDynamicCardVerificationCode");
        formatter.field("card_expiry_date", &"*** Sensitive Data Redacted ***");
        formatter.field("unpredictable_number", &self.unpredictable_number);
        formatter.field("application_transaction_counter", &self.application_transaction_counter);
        formatter.finish()
    }
}
impl DiscoverDynamicCardVerificationCode {
    /// Creates a new builder-style object to manufacture [`DiscoverDynamicCardVerificationCode`](crate::types::DiscoverDynamicCardVerificationCode).
    pub fn builder() -> crate::types::builders::DiscoverDynamicCardVerificationCodeBuilder {
        crate::types::builders::DiscoverDynamicCardVerificationCodeBuilder::default()
    }
}

/// A builder for [`DiscoverDynamicCardVerificationCode`](crate::types::DiscoverDynamicCardVerificationCode).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct DiscoverDynamicCardVerificationCodeBuilder {
    pub(crate) card_expiry_date: ::std::option::Option<::std::string::String>,
    pub(crate) unpredictable_number: ::std::option::Option<::std::string::String>,
    pub(crate) application_transaction_counter: ::std::option::Option<::std::string::String>,
}
impl DiscoverDynamicCardVerificationCodeBuilder {
    /// <p>The expiry date of a payment card.</p>
    /// This field is required.
    pub fn card_expiry_date(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.card_expiry_date = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The expiry date of a payment card.</p>
    pub fn set_card_expiry_date(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.card_expiry_date = input;
        self
    }
    /// <p>The expiry date of a payment card.</p>
    pub fn get_card_expiry_date(&self) -> &::std::option::Option<::std::string::String> {
        &self.card_expiry_date
    }
    /// <p>A random number that is generated by the issuer.</p>
    /// This field is required.
    pub fn unpredictable_number(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.unpredictable_number = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A random number that is generated by the issuer.</p>
    pub fn set_unpredictable_number(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.unpredictable_number = input;
        self
    }
    /// <p>A random number that is generated by the issuer.</p>
    pub fn get_unpredictable_number(&self) -> &::std::option::Option<::std::string::String> {
        &self.unpredictable_number
    }
    /// <p>The transaction counter value that comes from the terminal.</p>
    /// This field is required.
    pub fn application_transaction_counter(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.application_transaction_counter = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The transaction counter value that comes from the terminal.</p>
    pub fn set_application_transaction_counter(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.application_transaction_counter = input;
        self
    }
    /// <p>The transaction counter value that comes from the terminal.</p>
    pub fn get_application_transaction_counter(&self) -> &::std::option::Option<::std::string::String> {
        &self.application_transaction_counter
    }
    /// Consumes the builder and constructs a [`DiscoverDynamicCardVerificationCode`](crate::types::DiscoverDynamicCardVerificationCode).
    /// This method will fail if any of the following fields are not set:
    /// - [`card_expiry_date`](crate::types::builders::DiscoverDynamicCardVerificationCodeBuilder::card_expiry_date)
    /// - [`unpredictable_number`](crate::types::builders::DiscoverDynamicCardVerificationCodeBuilder::unpredictable_number)
    /// - [`application_transaction_counter`](crate::types::builders::DiscoverDynamicCardVerificationCodeBuilder::application_transaction_counter)
    pub fn build(self) -> ::std::result::Result<crate::types::DiscoverDynamicCardVerificationCode, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::DiscoverDynamicCardVerificationCode {
            card_expiry_date: self.card_expiry_date.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "card_expiry_date",
                    "card_expiry_date was not specified but it is required when building DiscoverDynamicCardVerificationCode",
                )
            })?,
            unpredictable_number: self.unpredictable_number.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "unpredictable_number",
                    "unpredictable_number was not specified but it is required when building DiscoverDynamicCardVerificationCode",
                )
            })?,
            application_transaction_counter: self.application_transaction_counter.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "application_transaction_counter",
                    "application_transaction_counter was not specified but it is required when building DiscoverDynamicCardVerificationCode",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for DiscoverDynamicCardVerificationCodeBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("DiscoverDynamicCardVerificationCodeBuilder");
        formatter.field("card_expiry_date", &"*** Sensitive Data Redacted ***");
        formatter.field("unpredictable_number", &self.unpredictable_number);
        formatter.field("application_transaction_counter", &self.application_transaction_counter);
        formatter.finish()
    }
}
