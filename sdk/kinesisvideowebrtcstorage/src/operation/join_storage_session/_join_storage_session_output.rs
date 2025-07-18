// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct JoinStorageSessionOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for JoinStorageSessionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl JoinStorageSessionOutput {
    /// Creates a new builder-style object to manufacture [`JoinStorageSessionOutput`](crate::operation::join_storage_session::JoinStorageSessionOutput).
    pub fn builder() -> crate::operation::join_storage_session::builders::JoinStorageSessionOutputBuilder {
        crate::operation::join_storage_session::builders::JoinStorageSessionOutputBuilder::default()
    }
}

/// A builder for [`JoinStorageSessionOutput`](crate::operation::join_storage_session::JoinStorageSessionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct JoinStorageSessionOutputBuilder {
    _request_id: Option<String>,
}
impl JoinStorageSessionOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`JoinStorageSessionOutput`](crate::operation::join_storage_session::JoinStorageSessionOutput).
    pub fn build(self) -> crate::operation::join_storage_session::JoinStorageSessionOutput {
        crate::operation::join_storage_session::JoinStorageSessionOutput {
            _request_id: self._request_id,
        }
    }
}
