// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UnregisterConnectorOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UnregisterConnectorOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UnregisterConnectorOutput {
    /// Creates a new builder-style object to manufacture [`UnregisterConnectorOutput`](crate::operation::unregister_connector::UnregisterConnectorOutput).
    pub fn builder() -> crate::operation::unregister_connector::builders::UnregisterConnectorOutputBuilder {
        crate::operation::unregister_connector::builders::UnregisterConnectorOutputBuilder::default()
    }
}

/// A builder for [`UnregisterConnectorOutput`](crate::operation::unregister_connector::UnregisterConnectorOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UnregisterConnectorOutputBuilder {
    _request_id: Option<String>,
}
impl UnregisterConnectorOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UnregisterConnectorOutput`](crate::operation::unregister_connector::UnregisterConnectorOutput).
    pub fn build(self) -> crate::operation::unregister_connector::UnregisterConnectorOutput {
        crate::operation::unregister_connector::UnregisterConnectorOutput {
            _request_id: self._request_id,
        }
    }
}
