// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Sends an AWS IoT Events input, passing in information about the detector model instance and the event that triggered the action.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IotEventsAction {
    /// <p>The name of the AWS IoT Events input where the data is sent.</p>
    pub input_name: ::std::string::String,
    /// <p>You can configure the action payload when you send a message to an AWS IoT Events input.</p>
    pub payload: ::std::option::Option<crate::types::Payload>,
}
impl IotEventsAction {
    /// <p>The name of the AWS IoT Events input where the data is sent.</p>
    pub fn input_name(&self) -> &str {
        use std::ops::Deref;
        self.input_name.deref()
    }
    /// <p>You can configure the action payload when you send a message to an AWS IoT Events input.</p>
    pub fn payload(&self) -> ::std::option::Option<&crate::types::Payload> {
        self.payload.as_ref()
    }
}
impl IotEventsAction {
    /// Creates a new builder-style object to manufacture [`IotEventsAction`](crate::types::IotEventsAction).
    pub fn builder() -> crate::types::builders::IotEventsActionBuilder {
        crate::types::builders::IotEventsActionBuilder::default()
    }
}

/// A builder for [`IotEventsAction`](crate::types::IotEventsAction).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IotEventsActionBuilder {
    pub(crate) input_name: ::std::option::Option<::std::string::String>,
    pub(crate) payload: ::std::option::Option<crate::types::Payload>,
}
impl IotEventsActionBuilder {
    /// <p>The name of the AWS IoT Events input where the data is sent.</p>
    /// This field is required.
    pub fn input_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.input_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the AWS IoT Events input where the data is sent.</p>
    pub fn set_input_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.input_name = input;
        self
    }
    /// <p>The name of the AWS IoT Events input where the data is sent.</p>
    pub fn get_input_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.input_name
    }
    /// <p>You can configure the action payload when you send a message to an AWS IoT Events input.</p>
    pub fn payload(mut self, input: crate::types::Payload) -> Self {
        self.payload = ::std::option::Option::Some(input);
        self
    }
    /// <p>You can configure the action payload when you send a message to an AWS IoT Events input.</p>
    pub fn set_payload(mut self, input: ::std::option::Option<crate::types::Payload>) -> Self {
        self.payload = input;
        self
    }
    /// <p>You can configure the action payload when you send a message to an AWS IoT Events input.</p>
    pub fn get_payload(&self) -> &::std::option::Option<crate::types::Payload> {
        &self.payload
    }
    /// Consumes the builder and constructs a [`IotEventsAction`](crate::types::IotEventsAction).
    /// This method will fail if any of the following fields are not set:
    /// - [`input_name`](crate::types::builders::IotEventsActionBuilder::input_name)
    pub fn build(self) -> ::std::result::Result<crate::types::IotEventsAction, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IotEventsAction {
            input_name: self.input_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "input_name",
                    "input_name was not specified but it is required when building IotEventsAction",
                )
            })?,
            payload: self.payload,
        })
    }
}
