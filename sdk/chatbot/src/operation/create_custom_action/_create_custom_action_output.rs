// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCustomActionOutput {
    /// <p>The fully defined ARN of the custom action.</p>
    pub custom_action_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateCustomActionOutput {
    /// <p>The fully defined ARN of the custom action.</p>
    pub fn custom_action_arn(&self) -> &str {
        use std::ops::Deref;
        self.custom_action_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCustomActionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCustomActionOutput {
    /// Creates a new builder-style object to manufacture [`CreateCustomActionOutput`](crate::operation::create_custom_action::CreateCustomActionOutput).
    pub fn builder() -> crate::operation::create_custom_action::builders::CreateCustomActionOutputBuilder {
        crate::operation::create_custom_action::builders::CreateCustomActionOutputBuilder::default()
    }
}

/// A builder for [`CreateCustomActionOutput`](crate::operation::create_custom_action::CreateCustomActionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCustomActionOutputBuilder {
    pub(crate) custom_action_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCustomActionOutputBuilder {
    /// <p>The fully defined ARN of the custom action.</p>
    /// This field is required.
    pub fn custom_action_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.custom_action_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The fully defined ARN of the custom action.</p>
    pub fn set_custom_action_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.custom_action_arn = input;
        self
    }
    /// <p>The fully defined ARN of the custom action.</p>
    pub fn get_custom_action_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.custom_action_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateCustomActionOutput`](crate::operation::create_custom_action::CreateCustomActionOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`custom_action_arn`](crate::operation::create_custom_action::builders::CreateCustomActionOutputBuilder::custom_action_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_custom_action::CreateCustomActionOutput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::create_custom_action::CreateCustomActionOutput {
            custom_action_arn: self.custom_action_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "custom_action_arn",
                    "custom_action_arn was not specified but it is required when building CreateCustomActionOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
