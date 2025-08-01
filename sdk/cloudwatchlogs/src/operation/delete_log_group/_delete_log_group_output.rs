// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteLogGroupOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteLogGroupOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteLogGroupOutput {
    /// Creates a new builder-style object to manufacture [`DeleteLogGroupOutput`](crate::operation::delete_log_group::DeleteLogGroupOutput).
    pub fn builder() -> crate::operation::delete_log_group::builders::DeleteLogGroupOutputBuilder {
        crate::operation::delete_log_group::builders::DeleteLogGroupOutputBuilder::default()
    }
}

/// A builder for [`DeleteLogGroupOutput`](crate::operation::delete_log_group::DeleteLogGroupOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteLogGroupOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteLogGroupOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteLogGroupOutput`](crate::operation::delete_log_group::DeleteLogGroupOutput).
    pub fn build(self) -> crate::operation::delete_log_group::DeleteLogGroupOutput {
        crate::operation::delete_log_group::DeleteLogGroupOutput {
            _request_id: self._request_id,
        }
    }
}
