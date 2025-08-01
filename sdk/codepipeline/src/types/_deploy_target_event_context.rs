// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The context for the event for the deploy action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeployTargetEventContext {
    /// <p>The command ID for the event for the deploy action.</p>
    pub ssm_command_id: ::std::option::Option<::std::string::String>,
    /// <p>The context message for the event for the deploy action.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl DeployTargetEventContext {
    /// <p>The command ID for the event for the deploy action.</p>
    pub fn ssm_command_id(&self) -> ::std::option::Option<&str> {
        self.ssm_command_id.as_deref()
    }
    /// <p>The context message for the event for the deploy action.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl DeployTargetEventContext {
    /// Creates a new builder-style object to manufacture [`DeployTargetEventContext`](crate::types::DeployTargetEventContext).
    pub fn builder() -> crate::types::builders::DeployTargetEventContextBuilder {
        crate::types::builders::DeployTargetEventContextBuilder::default()
    }
}

/// A builder for [`DeployTargetEventContext`](crate::types::DeployTargetEventContext).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeployTargetEventContextBuilder {
    pub(crate) ssm_command_id: ::std::option::Option<::std::string::String>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl DeployTargetEventContextBuilder {
    /// <p>The command ID for the event for the deploy action.</p>
    pub fn ssm_command_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ssm_command_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The command ID for the event for the deploy action.</p>
    pub fn set_ssm_command_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ssm_command_id = input;
        self
    }
    /// <p>The command ID for the event for the deploy action.</p>
    pub fn get_ssm_command_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ssm_command_id
    }
    /// <p>The context message for the event for the deploy action.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The context message for the event for the deploy action.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The context message for the event for the deploy action.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`DeployTargetEventContext`](crate::types::DeployTargetEventContext).
    pub fn build(self) -> crate::types::DeployTargetEventContext {
        crate::types::DeployTargetEventContext {
            ssm_command_id: self.ssm_command_id,
            message: self.message,
        }
    }
}
