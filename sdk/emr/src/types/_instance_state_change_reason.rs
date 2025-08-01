// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the status change reason for the instance.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InstanceStateChangeReason {
    /// <p>The programmable code for the state change reason.</p>
    pub code: ::std::option::Option<crate::types::InstanceStateChangeReasonCode>,
    /// <p>The status change reason description.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl InstanceStateChangeReason {
    /// <p>The programmable code for the state change reason.</p>
    pub fn code(&self) -> ::std::option::Option<&crate::types::InstanceStateChangeReasonCode> {
        self.code.as_ref()
    }
    /// <p>The status change reason description.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl InstanceStateChangeReason {
    /// Creates a new builder-style object to manufacture [`InstanceStateChangeReason`](crate::types::InstanceStateChangeReason).
    pub fn builder() -> crate::types::builders::InstanceStateChangeReasonBuilder {
        crate::types::builders::InstanceStateChangeReasonBuilder::default()
    }
}

/// A builder for [`InstanceStateChangeReason`](crate::types::InstanceStateChangeReason).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InstanceStateChangeReasonBuilder {
    pub(crate) code: ::std::option::Option<crate::types::InstanceStateChangeReasonCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl InstanceStateChangeReasonBuilder {
    /// <p>The programmable code for the state change reason.</p>
    pub fn code(mut self, input: crate::types::InstanceStateChangeReasonCode) -> Self {
        self.code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The programmable code for the state change reason.</p>
    pub fn set_code(mut self, input: ::std::option::Option<crate::types::InstanceStateChangeReasonCode>) -> Self {
        self.code = input;
        self
    }
    /// <p>The programmable code for the state change reason.</p>
    pub fn get_code(&self) -> &::std::option::Option<crate::types::InstanceStateChangeReasonCode> {
        &self.code
    }
    /// <p>The status change reason description.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The status change reason description.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>The status change reason description.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`InstanceStateChangeReason`](crate::types::InstanceStateChangeReason).
    pub fn build(self) -> crate::types::InstanceStateChangeReason {
        crate::types::InstanceStateChangeReason {
            code: self.code,
            message: self.message,
        }
    }
}
