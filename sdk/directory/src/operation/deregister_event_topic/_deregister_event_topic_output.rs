// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The result of a DeregisterEventTopic request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeregisterEventTopicOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeregisterEventTopicOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeregisterEventTopicOutput {
    /// Creates a new builder-style object to manufacture [`DeregisterEventTopicOutput`](crate::operation::deregister_event_topic::DeregisterEventTopicOutput).
    pub fn builder() -> crate::operation::deregister_event_topic::builders::DeregisterEventTopicOutputBuilder {
        crate::operation::deregister_event_topic::builders::DeregisterEventTopicOutputBuilder::default()
    }
}

/// A builder for [`DeregisterEventTopicOutput`](crate::operation::deregister_event_topic::DeregisterEventTopicOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeregisterEventTopicOutputBuilder {
    _request_id: Option<String>,
}
impl DeregisterEventTopicOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeregisterEventTopicOutput`](crate::operation::deregister_event_topic::DeregisterEventTopicOutput).
    pub fn build(self) -> crate::operation::deregister_event_topic::DeregisterEventTopicOutput {
        crate::operation::deregister_event_topic::DeregisterEventTopicOutput {
            _request_id: self._request_id,
        }
    }
}
