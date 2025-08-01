// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details of the ingested event.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IngestedEventsDetail {
    /// <p>The start and stop time of the ingested events.</p>
    pub ingested_events_time_window: ::std::option::Option<crate::types::IngestedEventsTimeWindow>,
}
impl IngestedEventsDetail {
    /// <p>The start and stop time of the ingested events.</p>
    pub fn ingested_events_time_window(&self) -> ::std::option::Option<&crate::types::IngestedEventsTimeWindow> {
        self.ingested_events_time_window.as_ref()
    }
}
impl IngestedEventsDetail {
    /// Creates a new builder-style object to manufacture [`IngestedEventsDetail`](crate::types::IngestedEventsDetail).
    pub fn builder() -> crate::types::builders::IngestedEventsDetailBuilder {
        crate::types::builders::IngestedEventsDetailBuilder::default()
    }
}

/// A builder for [`IngestedEventsDetail`](crate::types::IngestedEventsDetail).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IngestedEventsDetailBuilder {
    pub(crate) ingested_events_time_window: ::std::option::Option<crate::types::IngestedEventsTimeWindow>,
}
impl IngestedEventsDetailBuilder {
    /// <p>The start and stop time of the ingested events.</p>
    /// This field is required.
    pub fn ingested_events_time_window(mut self, input: crate::types::IngestedEventsTimeWindow) -> Self {
        self.ingested_events_time_window = ::std::option::Option::Some(input);
        self
    }
    /// <p>The start and stop time of the ingested events.</p>
    pub fn set_ingested_events_time_window(mut self, input: ::std::option::Option<crate::types::IngestedEventsTimeWindow>) -> Self {
        self.ingested_events_time_window = input;
        self
    }
    /// <p>The start and stop time of the ingested events.</p>
    pub fn get_ingested_events_time_window(&self) -> &::std::option::Option<crate::types::IngestedEventsTimeWindow> {
        &self.ingested_events_time_window
    }
    /// Consumes the builder and constructs a [`IngestedEventsDetail`](crate::types::IngestedEventsDetail).
    pub fn build(self) -> crate::types::IngestedEventsDetail {
        crate::types::IngestedEventsDetail {
            ingested_events_time_window: self.ingested_events_time_window,
        }
    }
}
