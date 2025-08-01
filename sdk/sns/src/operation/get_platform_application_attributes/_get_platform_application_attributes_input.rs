// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Input for <code>GetPlatformApplicationAttributes</code> action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetPlatformApplicationAttributesInput {
    /// <p><code>PlatformApplicationArn</code> for GetPlatformApplicationAttributesInput.</p>
    pub platform_application_arn: ::std::option::Option<::std::string::String>,
}
impl GetPlatformApplicationAttributesInput {
    /// <p><code>PlatformApplicationArn</code> for GetPlatformApplicationAttributesInput.</p>
    pub fn platform_application_arn(&self) -> ::std::option::Option<&str> {
        self.platform_application_arn.as_deref()
    }
}
impl GetPlatformApplicationAttributesInput {
    /// Creates a new builder-style object to manufacture [`GetPlatformApplicationAttributesInput`](crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesInput).
    pub fn builder() -> crate::operation::get_platform_application_attributes::builders::GetPlatformApplicationAttributesInputBuilder {
        crate::operation::get_platform_application_attributes::builders::GetPlatformApplicationAttributesInputBuilder::default()
    }
}

/// A builder for [`GetPlatformApplicationAttributesInput`](crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetPlatformApplicationAttributesInputBuilder {
    pub(crate) platform_application_arn: ::std::option::Option<::std::string::String>,
}
impl GetPlatformApplicationAttributesInputBuilder {
    /// <p><code>PlatformApplicationArn</code> for GetPlatformApplicationAttributesInput.</p>
    /// This field is required.
    pub fn platform_application_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.platform_application_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><code>PlatformApplicationArn</code> for GetPlatformApplicationAttributesInput.</p>
    pub fn set_platform_application_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.platform_application_arn = input;
        self
    }
    /// <p><code>PlatformApplicationArn</code> for GetPlatformApplicationAttributesInput.</p>
    pub fn get_platform_application_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.platform_application_arn
    }
    /// Consumes the builder and constructs a [`GetPlatformApplicationAttributesInput`](crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_platform_application_attributes::GetPlatformApplicationAttributesInput {
                platform_application_arn: self.platform_application_arn,
            },
        )
    }
}
