// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteSecurityProfileOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for DeleteSecurityProfileOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteSecurityProfileOutput {
    /// Creates a new builder-style object to manufacture [`DeleteSecurityProfileOutput`](crate::operation::delete_security_profile::DeleteSecurityProfileOutput).
    pub fn builder() -> crate::operation::delete_security_profile::builders::DeleteSecurityProfileOutputBuilder {
        crate::operation::delete_security_profile::builders::DeleteSecurityProfileOutputBuilder::default()
    }
}

/// A builder for [`DeleteSecurityProfileOutput`](crate::operation::delete_security_profile::DeleteSecurityProfileOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteSecurityProfileOutputBuilder {
    _request_id: Option<String>,
}
impl DeleteSecurityProfileOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteSecurityProfileOutput`](crate::operation::delete_security_profile::DeleteSecurityProfileOutput).
    pub fn build(self) -> crate::operation::delete_security_profile::DeleteSecurityProfileOutput {
        crate::operation::delete_security_profile::DeleteSecurityProfileOutput {
            _request_id: self._request_id,
        }
    }
}
