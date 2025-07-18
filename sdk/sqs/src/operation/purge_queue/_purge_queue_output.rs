// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PurgeQueueOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PurgeQueueOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PurgeQueueOutput {
    /// Creates a new builder-style object to manufacture [`PurgeQueueOutput`](crate::operation::purge_queue::PurgeQueueOutput).
    pub fn builder() -> crate::operation::purge_queue::builders::PurgeQueueOutputBuilder {
        crate::operation::purge_queue::builders::PurgeQueueOutputBuilder::default()
    }
}

/// A builder for [`PurgeQueueOutput`](crate::operation::purge_queue::PurgeQueueOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PurgeQueueOutputBuilder {
    _request_id: Option<String>,
}
impl PurgeQueueOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PurgeQueueOutput`](crate::operation::purge_queue::PurgeQueueOutput).
    pub fn build(self) -> crate::operation::purge_queue::PurgeQueueOutput {
        crate::operation::purge_queue::PurgeQueueOutput {
            _request_id: self._request_id,
        }
    }
}
