// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteUserPoolDomainOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteUserPoolDomainOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteUserPoolDomainOutput {
    /// Creates a new builder-style object to manufacture [`DeleteUserPoolDomainOutput`](crate::operation::delete_user_pool_domain::DeleteUserPoolDomainOutput).
    pub fn builder() -> crate::operation::delete_user_pool_domain::builders::DeleteUserPoolDomainOutputBuilder {
        crate::operation::delete_user_pool_domain::builders::DeleteUserPoolDomainOutputBuilder::default()
    }
}

/// A builder for [`DeleteUserPoolDomainOutput`](crate::operation::delete_user_pool_domain::DeleteUserPoolDomainOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteUserPoolDomainOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteUserPoolDomainOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteUserPoolDomainOutput`](crate::operation::delete_user_pool_domain::DeleteUserPoolDomainOutput).
    pub fn build(self) -> crate::operation::delete_user_pool_domain::DeleteUserPoolDomainOutput {
        crate::operation::delete_user_pool_domain::DeleteUserPoolDomainOutput {
            _request_id: self._request_id,
        }
    }
}
