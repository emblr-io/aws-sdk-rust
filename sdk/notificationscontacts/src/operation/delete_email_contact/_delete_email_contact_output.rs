// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteEmailContactOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteEmailContactOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteEmailContactOutput {
    /// Creates a new builder-style object to manufacture [`DeleteEmailContactOutput`](crate::operation::delete_email_contact::DeleteEmailContactOutput).
    pub fn builder() -> crate::operation::delete_email_contact::builders::DeleteEmailContactOutputBuilder {
        crate::operation::delete_email_contact::builders::DeleteEmailContactOutputBuilder::default()
    }
}

/// A builder for [`DeleteEmailContactOutput`](crate::operation::delete_email_contact::DeleteEmailContactOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteEmailContactOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteEmailContactOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteEmailContactOutput`](crate::operation::delete_email_contact::DeleteEmailContactOutput).
    pub fn build(self) -> crate::operation::delete_email_contact::DeleteEmailContactOutput {
        crate::operation::delete_email_contact::DeleteEmailContactOutput {
            _request_id: self._request_id,
        }
    }
}
