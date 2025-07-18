// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p><b>\[Event-based policies only\]</b> Specifies an event that activates an event-based policy.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EventSource {
    /// <p>The source of the event. Currently only managed CloudWatch Events rules are supported.</p>
    pub r#type: ::std::option::Option<crate::types::EventSourceValues>,
    /// <p>Information about the event.</p>
    pub parameters: ::std::option::Option<crate::types::EventParameters>,
}
impl EventSource {
    /// <p>The source of the event. Currently only managed CloudWatch Events rules are supported.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::EventSourceValues> {
        self.r#type.as_ref()
    }
    /// <p>Information about the event.</p>
    pub fn parameters(&self) -> ::std::option::Option<&crate::types::EventParameters> {
        self.parameters.as_ref()
    }
}
impl EventSource {
    /// Creates a new builder-style object to manufacture [`EventSource`](crate::types::EventSource).
    pub fn builder() -> crate::types::builders::EventSourceBuilder {
        crate::types::builders::EventSourceBuilder::default()
    }
}

/// A builder for [`EventSource`](crate::types::EventSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EventSourceBuilder {
    pub(crate) r#type: ::std::option::Option<crate::types::EventSourceValues>,
    pub(crate) parameters: ::std::option::Option<crate::types::EventParameters>,
}
impl EventSourceBuilder {
    /// <p>The source of the event. Currently only managed CloudWatch Events rules are supported.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::EventSourceValues) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source of the event. Currently only managed CloudWatch Events rules are supported.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::EventSourceValues>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The source of the event. Currently only managed CloudWatch Events rules are supported.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::EventSourceValues> {
        &self.r#type
    }
    /// <p>Information about the event.</p>
    pub fn parameters(mut self, input: crate::types::EventParameters) -> Self {
        self.parameters = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the event.</p>
    pub fn set_parameters(mut self, input: ::std::option::Option<crate::types::EventParameters>) -> Self {
        self.parameters = input;
        self
    }
    /// <p>Information about the event.</p>
    pub fn get_parameters(&self) -> &::std::option::Option<crate::types::EventParameters> {
        &self.parameters
    }
    /// Consumes the builder and constructs a [`EventSource`](crate::types::EventSource).
    pub fn build(self) -> crate::types::EventSource {
        crate::types::EventSource {
            r#type: self.r#type,
            parameters: self.parameters,
        }
    }
}
