// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutContactPolicyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for PutContactPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutContactPolicyOutput {
    /// Creates a new builder-style object to manufacture [`PutContactPolicyOutput`](crate::operation::put_contact_policy::PutContactPolicyOutput).
    pub fn builder() -> crate::operation::put_contact_policy::builders::PutContactPolicyOutputBuilder {
        crate::operation::put_contact_policy::builders::PutContactPolicyOutputBuilder::default()
    }
}

/// A builder for [`PutContactPolicyOutput`](crate::operation::put_contact_policy::PutContactPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutContactPolicyOutputBuilder {
    _request_id: Option<String>,
}
impl PutContactPolicyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutContactPolicyOutput`](crate::operation::put_contact_policy::PutContactPolicyOutput).
    pub fn build(self) -> crate::operation::put_contact_policy::PutContactPolicyOutput {
        crate::operation::put_contact_policy::PutContactPolicyOutput {
            _request_id: self._request_id,
        }
    }
}
