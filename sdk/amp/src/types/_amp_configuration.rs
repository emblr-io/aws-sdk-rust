// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The <code>AmpConfiguration</code> structure defines the Amazon Managed Service for Prometheus instance a scraper should send metrics to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AmpConfiguration {
    /// <p>ARN of the Amazon Managed Service for Prometheus workspace.</p>
    pub workspace_arn: ::std::string::String,
}
impl AmpConfiguration {
    /// <p>ARN of the Amazon Managed Service for Prometheus workspace.</p>
    pub fn workspace_arn(&self) -> &str {
        use std::ops::Deref;
        self.workspace_arn.deref()
    }
}
impl AmpConfiguration {
    /// Creates a new builder-style object to manufacture [`AmpConfiguration`](crate::types::AmpConfiguration).
    pub fn builder() -> crate::types::builders::AmpConfigurationBuilder {
        crate::types::builders::AmpConfigurationBuilder::default()
    }
}

/// A builder for [`AmpConfiguration`](crate::types::AmpConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AmpConfigurationBuilder {
    pub(crate) workspace_arn: ::std::option::Option<::std::string::String>,
}
impl AmpConfigurationBuilder {
    /// <p>ARN of the Amazon Managed Service for Prometheus workspace.</p>
    /// This field is required.
    pub fn workspace_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.workspace_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>ARN of the Amazon Managed Service for Prometheus workspace.</p>
    pub fn set_workspace_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.workspace_arn = input;
        self
    }
    /// <p>ARN of the Amazon Managed Service for Prometheus workspace.</p>
    pub fn get_workspace_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.workspace_arn
    }
    /// Consumes the builder and constructs a [`AmpConfiguration`](crate::types::AmpConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`workspace_arn`](crate::types::builders::AmpConfigurationBuilder::workspace_arn)
    pub fn build(self) -> ::std::result::Result<crate::types::AmpConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::AmpConfiguration {
            workspace_arn: self.workspace_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "workspace_arn",
                    "workspace_arn was not specified but it is required when building AmpConfiguration",
                )
            })?,
        })
    }
}
