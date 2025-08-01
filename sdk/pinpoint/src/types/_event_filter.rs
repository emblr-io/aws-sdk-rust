// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies the settings for an event that causes a campaign to be sent or a journey activity to be performed.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EventFilter {
    /// <p>The dimensions for the event filter to use for the campaign or the journey activity.</p>
    pub dimensions: ::std::option::Option<crate::types::EventDimensions>,
    /// <p>The type of event that causes the campaign to be sent or the journey activity to be performed. Valid values are: SYSTEM, sends the campaign or performs the activity when a system event occurs; and, ENDPOINT, sends the campaign or performs the activity when an endpoint event (
    /// <link linkend="apps-application-id-events">Events resource) occurs.</p>
    pub filter_type: ::std::option::Option<crate::types::FilterType>,
}
impl EventFilter {
    /// <p>The dimensions for the event filter to use for the campaign or the journey activity.</p>
    pub fn dimensions(&self) -> ::std::option::Option<&crate::types::EventDimensions> {
        self.dimensions.as_ref()
    }
    /// <p>The type of event that causes the campaign to be sent or the journey activity to be performed. Valid values are: SYSTEM, sends the campaign or performs the activity when a system event occurs; and, ENDPOINT, sends the campaign or performs the activity when an endpoint event (
    /// <link linkend="apps-application-id-events">Events resource) occurs.</p>
    pub fn filter_type(&self) -> ::std::option::Option<&crate::types::FilterType> {
        self.filter_type.as_ref()
    }
}
impl EventFilter {
    /// Creates a new builder-style object to manufacture [`EventFilter`](crate::types::EventFilter).
    pub fn builder() -> crate::types::builders::EventFilterBuilder {
        crate::types::builders::EventFilterBuilder::default()
    }
}

/// A builder for [`EventFilter`](crate::types::EventFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EventFilterBuilder {
    pub(crate) dimensions: ::std::option::Option<crate::types::EventDimensions>,
    pub(crate) filter_type: ::std::option::Option<crate::types::FilterType>,
}
impl EventFilterBuilder {
    /// <p>The dimensions for the event filter to use for the campaign or the journey activity.</p>
    /// This field is required.
    pub fn dimensions(mut self, input: crate::types::EventDimensions) -> Self {
        self.dimensions = ::std::option::Option::Some(input);
        self
    }
    /// <p>The dimensions for the event filter to use for the campaign or the journey activity.</p>
    pub fn set_dimensions(mut self, input: ::std::option::Option<crate::types::EventDimensions>) -> Self {
        self.dimensions = input;
        self
    }
    /// <p>The dimensions for the event filter to use for the campaign or the journey activity.</p>
    pub fn get_dimensions(&self) -> &::std::option::Option<crate::types::EventDimensions> {
        &self.dimensions
    }
    /// <p>The type of event that causes the campaign to be sent or the journey activity to be performed. Valid values are: SYSTEM, sends the campaign or performs the activity when a system event occurs; and, ENDPOINT, sends the campaign or performs the activity when an endpoint event (
    /// <link linkend="apps-application-id-events">Events resource) occurs.</p>
    /// This field is required.
    pub fn filter_type(mut self, input: crate::types::FilterType) -> Self {
        self.filter_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of event that causes the campaign to be sent or the journey activity to be performed. Valid values are: SYSTEM, sends the campaign or performs the activity when a system event occurs; and, ENDPOINT, sends the campaign or performs the activity when an endpoint event (
    /// <link linkend="apps-application-id-events">Events resource) occurs.</p>
    pub fn set_filter_type(mut self, input: ::std::option::Option<crate::types::FilterType>) -> Self {
        self.filter_type = input;
        self
    }
    /// <p>The type of event that causes the campaign to be sent or the journey activity to be performed. Valid values are: SYSTEM, sends the campaign or performs the activity when a system event occurs; and, ENDPOINT, sends the campaign or performs the activity when an endpoint event (
    /// <link linkend="apps-application-id-events">Events resource) occurs.</p>
    pub fn get_filter_type(&self) -> &::std::option::Option<crate::types::FilterType> {
        &self.filter_type
    }
    /// Consumes the builder and constructs a [`EventFilter`](crate::types::EventFilter).
    pub fn build(self) -> crate::types::EventFilter {
        crate::types::EventFilter {
            dimensions: self.dimensions,
            filter_type: self.filter_type,
        }
    }
}
