// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An empty element.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteHealthCheckOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteHealthCheckOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteHealthCheckOutput {
    /// Creates a new builder-style object to manufacture [`DeleteHealthCheckOutput`](crate::operation::delete_health_check::DeleteHealthCheckOutput).
    pub fn builder() -> crate::operation::delete_health_check::builders::DeleteHealthCheckOutputBuilder {
        crate::operation::delete_health_check::builders::DeleteHealthCheckOutputBuilder::default()
    }
}

/// A builder for [`DeleteHealthCheckOutput`](crate::operation::delete_health_check::DeleteHealthCheckOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteHealthCheckOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteHealthCheckOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteHealthCheckOutput`](crate::operation::delete_health_check::DeleteHealthCheckOutput).
    pub fn build(self) -> crate::operation::delete_health_check::DeleteHealthCheckOutput {
        crate::operation::delete_health_check::DeleteHealthCheckOutput {
            _request_id: self._request_id,
        }
    }
}
