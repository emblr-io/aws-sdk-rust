// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ModifyIdentityIdFormatOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for ModifyIdentityIdFormatOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ModifyIdentityIdFormatOutput {
    /// Creates a new builder-style object to manufacture [`ModifyIdentityIdFormatOutput`](crate::operation::modify_identity_id_format::ModifyIdentityIdFormatOutput).
    pub fn builder() -> crate::operation::modify_identity_id_format::builders::ModifyIdentityIdFormatOutputBuilder {
        crate::operation::modify_identity_id_format::builders::ModifyIdentityIdFormatOutputBuilder::default()
    }
}

/// A builder for [`ModifyIdentityIdFormatOutput`](crate::operation::modify_identity_id_format::ModifyIdentityIdFormatOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ModifyIdentityIdFormatOutputBuilder {
    _request_id: Option<String>,
}
impl ModifyIdentityIdFormatOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`ModifyIdentityIdFormatOutput`](crate::operation::modify_identity_id_format::ModifyIdentityIdFormatOutput).
    pub fn build(self) -> crate::operation::modify_identity_id_format::ModifyIdentityIdFormatOutput {
        crate::operation::modify_identity_id_format::ModifyIdentityIdFormatOutput {
            _request_id: self._request_id,
        }
    }
}
