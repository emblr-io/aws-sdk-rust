// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary that describes the suppressed email address.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SuppressedDestinationSummary {
    /// <p>The email address that's on the suppression list for your account.</p>
    pub email_address: ::std::string::String,
    /// <p>The reason that the address was added to the suppression list for your account.</p>
    pub reason: crate::types::SuppressionListReason,
    /// <p>The date and time when the suppressed destination was last updated, shown in Unix time format.</p>
    pub last_update_time: ::aws_smithy_types::DateTime,
}
impl SuppressedDestinationSummary {
    /// <p>The email address that's on the suppression list for your account.</p>
    pub fn email_address(&self) -> &str {
        use std::ops::Deref;
        self.email_address.deref()
    }
    /// <p>The reason that the address was added to the suppression list for your account.</p>
    pub fn reason(&self) -> &crate::types::SuppressionListReason {
        &self.reason
    }
    /// <p>The date and time when the suppressed destination was last updated, shown in Unix time format.</p>
    pub fn last_update_time(&self) -> &::aws_smithy_types::DateTime {
        &self.last_update_time
    }
}
impl SuppressedDestinationSummary {
    /// Creates a new builder-style object to manufacture [`SuppressedDestinationSummary`](crate::types::SuppressedDestinationSummary).
    pub fn builder() -> crate::types::builders::SuppressedDestinationSummaryBuilder {
        crate::types::builders::SuppressedDestinationSummaryBuilder::default()
    }
}

/// A builder for [`SuppressedDestinationSummary`](crate::types::SuppressedDestinationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SuppressedDestinationSummaryBuilder {
    pub(crate) email_address: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<crate::types::SuppressionListReason>,
    pub(crate) last_update_time: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl SuppressedDestinationSummaryBuilder {
    /// <p>The email address that's on the suppression list for your account.</p>
    /// This field is required.
    pub fn email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The email address that's on the suppression list for your account.</p>
    pub fn set_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.email_address = input;
        self
    }
    /// <p>The email address that's on the suppression list for your account.</p>
    pub fn get_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.email_address
    }
    /// <p>The reason that the address was added to the suppression list for your account.</p>
    /// This field is required.
    pub fn reason(mut self, input: crate::types::SuppressionListReason) -> Self {
        self.reason = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reason that the address was added to the suppression list for your account.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<crate::types::SuppressionListReason>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason that the address was added to the suppression list for your account.</p>
    pub fn get_reason(&self) -> &::std::option::Option<crate::types::SuppressionListReason> {
        &self.reason
    }
    /// <p>The date and time when the suppressed destination was last updated, shown in Unix time format.</p>
    /// This field is required.
    pub fn last_update_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_update_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time when the suppressed destination was last updated, shown in Unix time format.</p>
    pub fn set_last_update_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_update_time = input;
        self
    }
    /// <p>The date and time when the suppressed destination was last updated, shown in Unix time format.</p>
    pub fn get_last_update_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_update_time
    }
    /// Consumes the builder and constructs a [`SuppressedDestinationSummary`](crate::types::SuppressedDestinationSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`email_address`](crate::types::builders::SuppressedDestinationSummaryBuilder::email_address)
    /// - [`reason`](crate::types::builders::SuppressedDestinationSummaryBuilder::reason)
    /// - [`last_update_time`](crate::types::builders::SuppressedDestinationSummaryBuilder::last_update_time)
    pub fn build(self) -> ::std::result::Result<crate::types::SuppressedDestinationSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::SuppressedDestinationSummary {
            email_address: self.email_address.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "email_address",
                    "email_address was not specified but it is required when building SuppressedDestinationSummary",
                )
            })?,
            reason: self.reason.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "reason",
                    "reason was not specified but it is required when building SuppressedDestinationSummary",
                )
            })?,
            last_update_time: self.last_update_time.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "last_update_time",
                    "last_update_time was not specified but it is required when building SuppressedDestinationSummary",
                )
            })?,
        })
    }
}
