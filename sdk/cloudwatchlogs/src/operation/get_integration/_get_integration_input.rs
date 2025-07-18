// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetIntegrationInput {
    /// <p>The name of the integration that you want to find information about. To find the name of your integration, use <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListIntegrations.html">ListIntegrations</a></p>
    pub integration_name: ::std::option::Option<::std::string::String>,
}
impl GetIntegrationInput {
    /// <p>The name of the integration that you want to find information about. To find the name of your integration, use <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListIntegrations.html">ListIntegrations</a></p>
    pub fn integration_name(&self) -> ::std::option::Option<&str> {
        self.integration_name.as_deref()
    }
}
impl GetIntegrationInput {
    /// Creates a new builder-style object to manufacture [`GetIntegrationInput`](crate::operation::get_integration::GetIntegrationInput).
    pub fn builder() -> crate::operation::get_integration::builders::GetIntegrationInputBuilder {
        crate::operation::get_integration::builders::GetIntegrationInputBuilder::default()
    }
}

/// A builder for [`GetIntegrationInput`](crate::operation::get_integration::GetIntegrationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetIntegrationInputBuilder {
    pub(crate) integration_name: ::std::option::Option<::std::string::String>,
}
impl GetIntegrationInputBuilder {
    /// <p>The name of the integration that you want to find information about. To find the name of your integration, use <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListIntegrations.html">ListIntegrations</a></p>
    /// This field is required.
    pub fn integration_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.integration_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the integration that you want to find information about. To find the name of your integration, use <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListIntegrations.html">ListIntegrations</a></p>
    pub fn set_integration_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.integration_name = input;
        self
    }
    /// <p>The name of the integration that you want to find information about. To find the name of your integration, use <a href="https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_ListIntegrations.html">ListIntegrations</a></p>
    pub fn get_integration_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.integration_name
    }
    /// Consumes the builder and constructs a [`GetIntegrationInput`](crate::operation::get_integration::GetIntegrationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_integration::GetIntegrationInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_integration::GetIntegrationInput {
            integration_name: self.integration_name,
        })
    }
}
