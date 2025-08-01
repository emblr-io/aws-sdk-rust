// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RemoveApplicationInstanceOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for RemoveApplicationInstanceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl RemoveApplicationInstanceOutput {
    /// Creates a new builder-style object to manufacture [`RemoveApplicationInstanceOutput`](crate::operation::remove_application_instance::RemoveApplicationInstanceOutput).
    pub fn builder() -> crate::operation::remove_application_instance::builders::RemoveApplicationInstanceOutputBuilder {
        crate::operation::remove_application_instance::builders::RemoveApplicationInstanceOutputBuilder::default()
    }
}

/// A builder for [`RemoveApplicationInstanceOutput`](crate::operation::remove_application_instance::RemoveApplicationInstanceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RemoveApplicationInstanceOutputBuilder {
    _request_id: Option<String>,
}
impl RemoveApplicationInstanceOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`RemoveApplicationInstanceOutput`](crate::operation::remove_application_instance::RemoveApplicationInstanceOutput).
    pub fn build(self) -> crate::operation::remove_application_instance::RemoveApplicationInstanceOutput {
        crate::operation::remove_application_instance::RemoveApplicationInstanceOutput {
            _request_id: self._request_id,
        }
    }
}
