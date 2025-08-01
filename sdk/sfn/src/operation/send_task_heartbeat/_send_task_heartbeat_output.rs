// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SendTaskHeartbeatOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for SendTaskHeartbeatOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl SendTaskHeartbeatOutput {
    /// Creates a new builder-style object to manufacture [`SendTaskHeartbeatOutput`](crate::operation::send_task_heartbeat::SendTaskHeartbeatOutput).
    pub fn builder() -> crate::operation::send_task_heartbeat::builders::SendTaskHeartbeatOutputBuilder {
        crate::operation::send_task_heartbeat::builders::SendTaskHeartbeatOutputBuilder::default()
    }
}

/// A builder for [`SendTaskHeartbeatOutput`](crate::operation::send_task_heartbeat::SendTaskHeartbeatOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SendTaskHeartbeatOutputBuilder {
    _request_id: Option<String>,
}
impl SendTaskHeartbeatOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`SendTaskHeartbeatOutput`](crate::operation::send_task_heartbeat::SendTaskHeartbeatOutput).
    pub fn build(self) -> crate::operation::send_task_heartbeat::SendTaskHeartbeatOutput {
        crate::operation::send_task_heartbeat::SendTaskHeartbeatOutput {
            _request_id: self._request_id,
        }
    }
}
