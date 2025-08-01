// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteConfigurationSetEventDestinationInput {
    /// ConfigurationSetName
    pub configuration_set_name: ::std::option::Option<::std::string::String>,
    /// EventDestinationName
    pub event_destination_name: ::std::option::Option<::std::string::String>,
}
impl DeleteConfigurationSetEventDestinationInput {
    /// ConfigurationSetName
    pub fn configuration_set_name(&self) -> ::std::option::Option<&str> {
        self.configuration_set_name.as_deref()
    }
    /// EventDestinationName
    pub fn event_destination_name(&self) -> ::std::option::Option<&str> {
        self.event_destination_name.as_deref()
    }
}
impl DeleteConfigurationSetEventDestinationInput {
    /// Creates a new builder-style object to manufacture [`DeleteConfigurationSetEventDestinationInput`](crate::operation::delete_configuration_set_event_destination::DeleteConfigurationSetEventDestinationInput).
    pub fn builder() -> crate::operation::delete_configuration_set_event_destination::builders::DeleteConfigurationSetEventDestinationInputBuilder {
        crate::operation::delete_configuration_set_event_destination::builders::DeleteConfigurationSetEventDestinationInputBuilder::default()
    }
}

/// A builder for [`DeleteConfigurationSetEventDestinationInput`](crate::operation::delete_configuration_set_event_destination::DeleteConfigurationSetEventDestinationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteConfigurationSetEventDestinationInputBuilder {
    pub(crate) configuration_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) event_destination_name: ::std::option::Option<::std::string::String>,
}
impl DeleteConfigurationSetEventDestinationInputBuilder {
    /// ConfigurationSetName
    /// This field is required.
    pub fn configuration_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.configuration_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// ConfigurationSetName
    pub fn set_configuration_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.configuration_set_name = input;
        self
    }
    /// ConfigurationSetName
    pub fn get_configuration_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.configuration_set_name
    }
    /// EventDestinationName
    /// This field is required.
    pub fn event_destination_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_destination_name = ::std::option::Option::Some(input.into());
        self
    }
    /// EventDestinationName
    pub fn set_event_destination_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_destination_name = input;
        self
    }
    /// EventDestinationName
    pub fn get_event_destination_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_destination_name
    }
    /// Consumes the builder and constructs a [`DeleteConfigurationSetEventDestinationInput`](crate::operation::delete_configuration_set_event_destination::DeleteConfigurationSetEventDestinationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_configuration_set_event_destination::DeleteConfigurationSetEventDestinationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::delete_configuration_set_event_destination::DeleteConfigurationSetEventDestinationInput {
                configuration_set_name: self.configuration_set_name,
                event_destination_name: self.event_destination_name,
            },
        )
    }
}
