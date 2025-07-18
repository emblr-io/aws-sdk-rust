// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// Default Email Outbound config
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct EmailOutboundConfig {
    /// Source/Destination Email address used for Email messages
    pub connect_source_email_address: ::std::string::String,
    /// Display name for Email Address
    pub source_email_address_display_name: ::std::option::Option<::std::string::String>,
    /// Amazon Resource Names(ARN)
    pub wisdom_template_arn: ::std::string::String,
}
impl EmailOutboundConfig {
    /// Source/Destination Email address used for Email messages
    pub fn connect_source_email_address(&self) -> &str {
        use std::ops::Deref;
        self.connect_source_email_address.deref()
    }
    /// Display name for Email Address
    pub fn source_email_address_display_name(&self) -> ::std::option::Option<&str> {
        self.source_email_address_display_name.as_deref()
    }
    /// Amazon Resource Names(ARN)
    pub fn wisdom_template_arn(&self) -> &str {
        use std::ops::Deref;
        self.wisdom_template_arn.deref()
    }
}
impl ::std::fmt::Debug for EmailOutboundConfig {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EmailOutboundConfig");
        formatter.field("connect_source_email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("source_email_address_display_name", &"*** Sensitive Data Redacted ***");
        formatter.field("wisdom_template_arn", &self.wisdom_template_arn);
        formatter.finish()
    }
}
impl EmailOutboundConfig {
    /// Creates a new builder-style object to manufacture [`EmailOutboundConfig`](crate::types::EmailOutboundConfig).
    pub fn builder() -> crate::types::builders::EmailOutboundConfigBuilder {
        crate::types::builders::EmailOutboundConfigBuilder::default()
    }
}

/// A builder for [`EmailOutboundConfig`](crate::types::EmailOutboundConfig).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct EmailOutboundConfigBuilder {
    pub(crate) connect_source_email_address: ::std::option::Option<::std::string::String>,
    pub(crate) source_email_address_display_name: ::std::option::Option<::std::string::String>,
    pub(crate) wisdom_template_arn: ::std::option::Option<::std::string::String>,
}
impl EmailOutboundConfigBuilder {
    /// Source/Destination Email address used for Email messages
    /// This field is required.
    pub fn connect_source_email_address(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.connect_source_email_address = ::std::option::Option::Some(input.into());
        self
    }
    /// Source/Destination Email address used for Email messages
    pub fn set_connect_source_email_address(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.connect_source_email_address = input;
        self
    }
    /// Source/Destination Email address used for Email messages
    pub fn get_connect_source_email_address(&self) -> &::std::option::Option<::std::string::String> {
        &self.connect_source_email_address
    }
    /// Display name for Email Address
    pub fn source_email_address_display_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.source_email_address_display_name = ::std::option::Option::Some(input.into());
        self
    }
    /// Display name for Email Address
    pub fn set_source_email_address_display_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.source_email_address_display_name = input;
        self
    }
    /// Display name for Email Address
    pub fn get_source_email_address_display_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.source_email_address_display_name
    }
    /// Amazon Resource Names(ARN)
    /// This field is required.
    pub fn wisdom_template_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.wisdom_template_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// Amazon Resource Names(ARN)
    pub fn set_wisdom_template_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.wisdom_template_arn = input;
        self
    }
    /// Amazon Resource Names(ARN)
    pub fn get_wisdom_template_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.wisdom_template_arn
    }
    /// Consumes the builder and constructs a [`EmailOutboundConfig`](crate::types::EmailOutboundConfig).
    /// This method will fail if any of the following fields are not set:
    /// - [`connect_source_email_address`](crate::types::builders::EmailOutboundConfigBuilder::connect_source_email_address)
    /// - [`wisdom_template_arn`](crate::types::builders::EmailOutboundConfigBuilder::wisdom_template_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::EmailOutboundConfig, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::EmailOutboundConfig {
            connect_source_email_address: self.connect_source_email_address.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "connect_source_email_address",
                    "connect_source_email_address was not specified but it is required when building EmailOutboundConfig",
                )
            })?,
            source_email_address_display_name: self.source_email_address_display_name,
            wisdom_template_arn: self.wisdom_template_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "wisdom_template_arn",
                    "wisdom_template_arn was not specified but it is required when building EmailOutboundConfig",
                )
            })?,
        })
    }
}
impl ::std::fmt::Debug for EmailOutboundConfigBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("EmailOutboundConfigBuilder");
        formatter.field("connect_source_email_address", &"*** Sensitive Data Redacted ***");
        formatter.field("source_email_address_display_name", &"*** Sensitive Data Redacted ***");
        formatter.field("wisdom_template_arn", &self.wisdom_template_arn);
        formatter.finish()
    }
}
