// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopStackOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for StopStackOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopStackOutput {
    /// Creates a new builder-style object to manufacture [`StopStackOutput`](crate::operation::stop_stack::StopStackOutput).
    pub fn builder() -> crate::operation::stop_stack::builders::StopStackOutputBuilder {
        crate::operation::stop_stack::builders::StopStackOutputBuilder::default()
    }
}

/// A builder for [`StopStackOutput`](crate::operation::stop_stack::StopStackOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopStackOutputBuilder {
    _request_id: Option<String>,
}
impl StopStackOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopStackOutput`](crate::operation::stop_stack::StopStackOutput).
    pub fn build(self) -> crate::operation::stop_stack::StopStackOutput {
        crate::operation::stop_stack::StopStackOutput {
            _request_id: self._request_id,
        }
    }
}
