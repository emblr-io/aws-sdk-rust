// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeEventSourcesConfigOutput {
    /// <p>Lists the event sources in the configuration.</p>
    pub event_sources: ::std::option::Option<crate::types::EventSourcesConfig>,
    _request_id: Option<String>,
}
impl DescribeEventSourcesConfigOutput {
    /// <p>Lists the event sources in the configuration.</p>
    pub fn event_sources(&self) -> ::std::option::Option<&crate::types::EventSourcesConfig> {
        self.event_sources.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeEventSourcesConfigOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeEventSourcesConfigOutput {
    /// Creates a new builder-style object to manufacture [`DescribeEventSourcesConfigOutput`](crate::operation::describe_event_sources_config::DescribeEventSourcesConfigOutput).
    pub fn builder() -> crate::operation::describe_event_sources_config::builders::DescribeEventSourcesConfigOutputBuilder {
        crate::operation::describe_event_sources_config::builders::DescribeEventSourcesConfigOutputBuilder::default()
    }
}

/// A builder for [`DescribeEventSourcesConfigOutput`](crate::operation::describe_event_sources_config::DescribeEventSourcesConfigOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeEventSourcesConfigOutputBuilder {
    pub(crate) event_sources: ::std::option::Option<crate::types::EventSourcesConfig>,
    _request_id: Option<String>,
}
impl DescribeEventSourcesConfigOutputBuilder {
    /// <p>Lists the event sources in the configuration.</p>
    pub fn event_sources(mut self, input: crate::types::EventSourcesConfig) -> Self {
        self.event_sources = ::std::option::Option::Some(input);
        self
    }
    /// <p>Lists the event sources in the configuration.</p>
    pub fn set_event_sources(mut self, input: ::std::option::Option<crate::types::EventSourcesConfig>) -> Self {
        self.event_sources = input;
        self
    }
    /// <p>Lists the event sources in the configuration.</p>
    pub fn get_event_sources(&self) -> &::std::option::Option<crate::types::EventSourcesConfig> {
        &self.event_sources
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeEventSourcesConfigOutput`](crate::operation::describe_event_sources_config::DescribeEventSourcesConfigOutput).
    pub fn build(self) -> crate::operation::describe_event_sources_config::DescribeEventSourcesConfigOutput {
        crate::operation::describe_event_sources_config::DescribeEventSourcesConfigOutput {
            event_sources: self.event_sources,
            _request_id: self._request_id,
        }
    }
}
