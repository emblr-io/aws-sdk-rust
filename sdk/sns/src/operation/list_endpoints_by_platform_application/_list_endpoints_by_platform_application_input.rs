// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input for <code>ListEndpointsByPlatformApplication</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEndpointsByPlatformApplicationInput {
    /// <p><code>PlatformApplicationArn</code> for <code>ListEndpointsByPlatformApplicationInput</code> action.</p>
    pub platform_application_arn: ::std::option::Option<::std::string::String>,
    /// <p><code>NextToken</code> string is used when calling <code>ListEndpointsByPlatformApplication</code> action to retrieve additional records that are available after the first page results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListEndpointsByPlatformApplicationInput {
    /// <p><code>PlatformApplicationArn</code> for <code>ListEndpointsByPlatformApplicationInput</code> action.</p>
    pub fn platform_application_arn(&self) -> ::std::option::Option<&str> {
        self.platform_application_arn.as_deref()
    }
    /// <p><code>NextToken</code> string is used when calling <code>ListEndpointsByPlatformApplication</code> action to retrieve additional records that are available after the first page results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListEndpointsByPlatformApplicationInput {
    /// Creates a new builder-style object to manufacture [`ListEndpointsByPlatformApplicationInput`](crate::operation::list_endpoints_by_platform_application::ListEndpointsByPlatformApplicationInput).
    pub fn builder() -> crate::operation::list_endpoints_by_platform_application::builders::ListEndpointsByPlatformApplicationInputBuilder {
        crate::operation::list_endpoints_by_platform_application::builders::ListEndpointsByPlatformApplicationInputBuilder::default()
    }
}

/// A builder for [`ListEndpointsByPlatformApplicationInput`](crate::operation::list_endpoints_by_platform_application::ListEndpointsByPlatformApplicationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEndpointsByPlatformApplicationInputBuilder {
    pub(crate) platform_application_arn: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListEndpointsByPlatformApplicationInputBuilder {
    /// <p><code>PlatformApplicationArn</code> for <code>ListEndpointsByPlatformApplicationInput</code> action.</p>
    /// This field is required.
    pub fn platform_application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform_application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>PlatformApplicationArn</code> for <code>ListEndpointsByPlatformApplicationInput</code> action.</p>
    pub fn set_platform_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform_application_arn = input;
        self
    }
    /// <p><code>PlatformApplicationArn</code> for <code>ListEndpointsByPlatformApplicationInput</code> action.</p>
    pub fn get_platform_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform_application_arn
    }
    /// <p><code>NextToken</code> string is used when calling <code>ListEndpointsByPlatformApplication</code> action to retrieve additional records that are available after the first page results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>NextToken</code> string is used when calling <code>ListEndpointsByPlatformApplication</code> action to retrieve additional records that are available after the first page results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p><code>NextToken</code> string is used when calling <code>ListEndpointsByPlatformApplication</code> action to retrieve additional records that are available after the first page results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListEndpointsByPlatformApplicationInput`](crate::operation::list_endpoints_by_platform_application::ListEndpointsByPlatformApplicationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_endpoints_by_platform_application::ListEndpointsByPlatformApplicationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_endpoints_by_platform_application::ListEndpointsByPlatformApplicationInput {
                platform_application_arn: self.platform_application_arn,
                next_token: self.next_token,
            },
        )
    }
}
