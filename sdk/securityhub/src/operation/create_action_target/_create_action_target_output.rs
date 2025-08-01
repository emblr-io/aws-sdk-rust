// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateActionTargetOutput {
    /// <p>The Amazon Resource Name (ARN) for the custom action target.</p>
    pub action_target_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateActionTargetOutput {
    /// <p>The Amazon Resource Name (ARN) for the custom action target.</p>
    pub fn action_target_arn(&self) -> ::std::option::Option<&str> {
        self.action_target_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateActionTargetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateActionTargetOutput {
    /// Creates a new builder-style object to manufacture [`CreateActionTargetOutput`](crate::operation::create_action_target::CreateActionTargetOutput).
    pub fn builder() -> crate::operation::create_action_target::builders::CreateActionTargetOutputBuilder {
        crate::operation::create_action_target::builders::CreateActionTargetOutputBuilder::default()
    }
}

/// A builder for [`CreateActionTargetOutput`](crate::operation::create_action_target::CreateActionTargetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateActionTargetOutputBuilder {
    pub(crate) action_target_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateActionTargetOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) for the custom action target.</p>
    /// This field is required.
    pub fn action_target_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.action_target_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the custom action target.</p>
    pub fn set_action_target_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.action_target_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the custom action target.</p>
    pub fn get_action_target_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.action_target_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateActionTargetOutput`](crate::operation::create_action_target::CreateActionTargetOutput).
    pub fn build(self) -> crate::operation::create_action_target::CreateActionTargetOutput {
        crate::operation::create_action_target::CreateActionTargetOutput {
            action_target_arn: self.action_target_arn,
            _request_id: self._request_id,
        }
    }
}
