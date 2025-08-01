// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SetDefaultMessageFeedbackEnabledOutput {
    /// <p>The arn of the configuration set.</p>
    pub configuration_set_arn: ::std::option::Option<::std::string::String>,
    /// <p>The name of the configuration.</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// <p>True if message feedback is enabled.</p>
    pub message_feedback_enabled: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl SetDefaultMessageFeedbackEnabledOutput {
    /// <p>The arn of the configuration set.</p>
    pub fn configuration_set_arn(&self) -> ::std::option::Option<&str> {
        self.configuration_set_arn.as_deref()
    }
    /// <p>The name of the configuration.</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// <p>True if message feedback is enabled.</p>
    pub fn message_feedback_enabled(&self) -> ::std::option::Option<bool> {
        self.message_feedback_enabled
    }
}
impl ::aws_types::request_id::RequestId for SetDefaultMessageFeedbackEnabledOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SetDefaultMessageFeedbackEnabledOutput {
    /// Creates a new builder-style object to manufacture [`SetDefaultMessageFeedbackEnabledOutput`](crate::operation::set_default_message_feedback_enabled::SetDefaultMessageFeedbackEnabledOutput).
    pub fn builder() -> crate::operation::set_default_message_feedback_enabled::builders::SetDefaultMessageFeedbackEnabledOutputBuilder {
        crate::operation::set_default_message_feedback_enabled::builders::SetDefaultMessageFeedbackEnabledOutputBuilder::default()
    }
}

/// A builder for [`SetDefaultMessageFeedbackEnabledOutput`](crate::operation::set_default_message_feedback_enabled::SetDefaultMessageFeedbackEnabledOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SetDefaultMessageFeedbackEnabledOutputBuilder {
    pub(crate) configuration_set_arn: ::std::option::Option<::std::string::String>,
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) message_feedback_enabled: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl SetDefaultMessageFeedbackEnabledOutputBuilder {
    /// <p>The arn of the configuration set.</p>
    pub fn configuration_set_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The arn of the configuration set.</p>
    pub fn set_configuration_set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_arn = input;
        self
    }
    /// <p>The arn of the configuration set.</p>
    pub fn get_configuration_set_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_arn
    }
    /// <p>The name of the configuration.</p>
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration.</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration.</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// <p>True if message feedback is enabled.</p>
    pub fn message_feedback_enabled(mut self, input: bool) -> Self {
        self.message_feedback_enabled = ::std::option::Option::Some(input);
        self
    }
    /// <p>True if message feedback is enabled.</p>
    pub fn set_message_feedback_enabled(mut self, input: ::std::option::Option<bool>) -> Self {
        self.message_feedback_enabled = input;
        self
    }
    /// <p>True if message feedback is enabled.</p>
    pub fn get_message_feedback_enabled(&self) -> &::std::option::Option<bool> {
        &self.message_feedback_enabled
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SetDefaultMessageFeedbackEnabledOutput`](crate::operation::set_default_message_feedback_enabled::SetDefaultMessageFeedbackEnabledOutput).
    pub fn build(self) -> crate::operation::set_default_message_feedback_enabled::SetDefaultMessageFeedbackEnabledOutput {
        crate::operation::set_default_message_feedback_enabled::SetDefaultMessageFeedbackEnabledOutput {
            configuration_set_arn: self.configuration_set_arn,
            configuration_set_name: self.configuration_set_name,
            message_feedback_enabled: self.message_feedback_enabled,
            _request_id: self._request_id,
        }
    }
}
