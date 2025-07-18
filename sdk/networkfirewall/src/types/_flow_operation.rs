// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information about a flow operation, such as related statuses, unique identifiers, and all filters defined in the operation.</p>
/// <p>Flow operations let you manage the flows tracked in the flow table, also known as the firewall table.</p>
/// <p>A flow is network traffic that is monitored by a firewall, either by stateful or stateless rules. For traffic to be considered part of a flow, it must share Destination, DestinationPort, Direction, Protocol, Source, and SourcePort.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct FlowOperation {
    /// <p>The reqested <code>FlowOperation</code> ignores flows with an age (in seconds) lower than <code>MinimumFlowAgeInSeconds</code>. You provide this for start commands.</p>
    pub minimum_flow_age_in_seconds: ::std::option::Option<i32>,
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub flow_filters: ::std::option::Option<::std::vec::Vec<crate::types::FlowFilter>>,
}
impl FlowOperation {
    /// <p>The reqested <code>FlowOperation</code> ignores flows with an age (in seconds) lower than <code>MinimumFlowAgeInSeconds</code>. You provide this for start commands.</p>
    pub fn minimum_flow_age_in_seconds(&self) -> ::std::option::Option<i32> {
        self.minimum_flow_age_in_seconds
    }
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.flow_filters.is_none()`.
    pub fn flow_filters(&self) -> &[crate::types::FlowFilter] {
        self.flow_filters.as_deref().unwrap_or_default()
    }
}
impl FlowOperation {
    /// Creates a new builder-style object to manufacture [`FlowOperation`](crate::types::FlowOperation).
    pub fn builder() -> crate::types::builders::FlowOperationBuilder {
        crate::types::builders::FlowOperationBuilder::default()
    }
}

/// A builder for [`FlowOperation`](crate::types::FlowOperation).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct FlowOperationBuilder {
    pub(crate) minimum_flow_age_in_seconds: ::std::option::Option<i32>,
    pub(crate) flow_filters: ::std::option::Option<::std::vec::Vec<crate::types::FlowFilter>>,
}
impl FlowOperationBuilder {
    /// <p>The reqested <code>FlowOperation</code> ignores flows with an age (in seconds) lower than <code>MinimumFlowAgeInSeconds</code>. You provide this for start commands.</p>
    pub fn minimum_flow_age_in_seconds(mut self, input: i32) -> Self {
        self.minimum_flow_age_in_seconds = ::std::option::Option::Some(input);
        self
    }
    /// <p>The reqested <code>FlowOperation</code> ignores flows with an age (in seconds) lower than <code>MinimumFlowAgeInSeconds</code>. You provide this for start commands.</p>
    pub fn set_minimum_flow_age_in_seconds(mut self, input: ::std::option::Option<i32>) -> Self {
        self.minimum_flow_age_in_seconds = input;
        self
    }
    /// <p>The reqested <code>FlowOperation</code> ignores flows with an age (in seconds) lower than <code>MinimumFlowAgeInSeconds</code>. You provide this for start commands.</p>
    pub fn get_minimum_flow_age_in_seconds(&self) -> &::std::option::Option<i32> {
        &self.minimum_flow_age_in_seconds
    }
    /// Appends an item to `flow_filters`.
    ///
    /// To override the contents of this collection use [`set_flow_filters`](Self::set_flow_filters).
    ///
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn flow_filters(mut self, input: crate::types::FlowFilter) -> Self {
        let mut v = self.flow_filters.unwrap_or_default();
        v.push(input);
        self.flow_filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn set_flow_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::FlowFilter>>) -> Self {
        self.flow_filters = input;
        self
    }
    /// <p>Defines the scope a flow operation. You can use up to 20 filters to configure a single flow operation.</p>
    pub fn get_flow_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::FlowFilter>> {
        &self.flow_filters
    }
    /// Consumes the builder and constructs a [`FlowOperation`](crate::types::FlowOperation).
    pub fn build(self) -> crate::types::FlowOperation {
        crate::types::FlowOperation {
            minimum_flow_age_in_seconds: self.minimum_flow_age_in_seconds,
            flow_filters: self.flow_filters,
        }
    }
}
