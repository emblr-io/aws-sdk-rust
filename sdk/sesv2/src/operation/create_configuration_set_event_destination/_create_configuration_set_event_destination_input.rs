// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A request to add an event destination to a configuration set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateConfigurationSetEventDestinationInput {
    /// <p>The name of the configuration set .</p>
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// <p>A name that identifies the event destination within the configuration set.</p>
    pub event_destination_name: ::std::option::Option<::std::string::String>,
    /// <p>An object that defines the event destination.</p>
    pub event_destination: ::std::option::Option<crate::types::EventDestinationDefinition>,
}
impl CreateConfigurationSetEventDestinationInput {
    /// <p>The name of the configuration set .</p>
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// <p>A name that identifies the event destination within the configuration set.</p>
    pub fn event_destination_name(&self) -> ::std::option::Option<&str> {
        self.event_destination_name.as_deref()
    }
    /// <p>An object that defines the event destination.</p>
    pub fn event_destination(&self) -> ::std::option::Option<&crate::types::EventDestinationDefinition> {
        self.event_destination.as_ref()
    }
}
impl CreateConfigurationSetEventDestinationInput {
    /// Creates a new builder-style object to manufacture [`CreateConfigurationSetEventDestinationInput`](crate::operation::create_configuration_set_event_destination::CreateConfigurationSetEventDestinationInput).
    pub fn builder() -> crate::operation::create_configuration_set_event_destination::builders::CreateConfigurationSetEventDestinationInputBuilder {
        crate::operation::create_configuration_set_event_destination::builders::CreateConfigurationSetEventDestinationInputBuilder::default()
    }
}

/// A builder for [`CreateConfigurationSetEventDestinationInput`](crate::operation::create_configuration_set_event_destination::CreateConfigurationSetEventDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateConfigurationSetEventDestinationInputBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) event_destination_name: ::std::option::Option<::std::string::String>,
    pub(crate) event_destination: ::std::option::Option<crate::types::EventDestinationDefinition>,
}
impl CreateConfigurationSetEventDestinationInputBuilder {
    /// <p>The name of the configuration set .</p>
    /// This field is required.
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the configuration set .</p>
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// <p>The name of the configuration set .</p>
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// <p>A name that identifies the event destination within the configuration set.</p>
    /// This field is required.
    pub fn event_destination_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_destination_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name that identifies the event destination within the configuration set.</p>
    pub fn set_event_destination_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_destination_name = input;
        self
    }
    /// <p>A name that identifies the event destination within the configuration set.</p>
    pub fn get_event_destination_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_destination_name
    }
    /// <p>An object that defines the event destination.</p>
    /// This field is required.
    pub fn event_destination(mut self, input: crate::types::EventDestinationDefinition) -> Self {
        self.event_destination = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that defines the event destination.</p>
    pub fn set_event_destination(mut self, input: ::std::option::Option<crate::types::EventDestinationDefinition>) -> Self {
        self.event_destination = input;
        self
    }
    /// <p>An object that defines the event destination.</p>
    pub fn get_event_destination(&self) -> &::std::option::Option<crate::types::EventDestinationDefinition> {
        &self.event_destination
    }
    /// Consumes the builder and constructs a [`CreateConfigurationSetEventDestinationInput`](crate::operation::create_configuration_set_event_destination::CreateConfigurationSetEventDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_configuration_set_event_destination::CreateConfigurationSetEventDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_configuration_set_event_destination::CreateConfigurationSetEventDestinationInput {
                configuration_set_name: self.configuration_set_name,
                event_destination_name: self.event_destination_name,
                event_destination: self.event_destination,
            },
        )
    }
}
