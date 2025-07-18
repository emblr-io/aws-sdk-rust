// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutLoggingOptionsOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutLoggingOptionsOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutLoggingOptionsOutput {
    /// Creates a new builder-style object to manufacture [`PutLoggingOptionsOutput`](crate::operation::put_logging_options::PutLoggingOptionsOutput).
    pub fn builder() -> crate::operation::put_logging_options::builders::PutLoggingOptionsOutputBuilder {
        crate::operation::put_logging_options::builders::PutLoggingOptionsOutputBuilder::default()
    }
}

/// A builder for [`PutLoggingOptionsOutput`](crate::operation::put_logging_options::PutLoggingOptionsOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutLoggingOptionsOutputBuilder {
    _request_id: Option<String>,
}
impl PutLoggingOptionsOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutLoggingOptionsOutput`](crate::operation::put_logging_options::PutLoggingOptionsOutput).
    pub fn build(self) -> crate::operation::put_logging_options::PutLoggingOptionsOutput {
        crate::operation::put_logging_options::PutLoggingOptionsOutput {
            _request_id: self._request_id,
        }
    }
}
