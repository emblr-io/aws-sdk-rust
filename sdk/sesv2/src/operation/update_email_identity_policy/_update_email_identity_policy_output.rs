// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>An HTTP 200 response if the request succeeds, or an error message if the request fails.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateEmailIdentityPolicyOutput {
    _request_id: Option<String>,
}
impl ::aws_types::request_id::RequestId for UpdateEmailIdentityPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateEmailIdentityPolicyOutput {
    /// Creates a new builder-style object to manufacture [`UpdateEmailIdentityPolicyOutput`](crate::operation::update_email_identity_policy::UpdateEmailIdentityPolicyOutput).
    pub fn builder() -> crate::operation::update_email_identity_policy::builders::UpdateEmailIdentityPolicyOutputBuilder {
        crate::operation::update_email_identity_policy::builders::UpdateEmailIdentityPolicyOutputBuilder::default()
    }
}

/// A builder for [`UpdateEmailIdentityPolicyOutput`](crate::operation::update_email_identity_policy::UpdateEmailIdentityPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateEmailIdentityPolicyOutputBuilder {
    _request_id: Option<String>,
}
impl UpdateEmailIdentityPolicyOutputBuilder {
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateEmailIdentityPolicyOutput`](crate::operation::update_email_identity_policy::UpdateEmailIdentityPolicyOutput).
    pub fn build(self) -> crate::operation::update_email_identity_policy::UpdateEmailIdentityPolicyOutput {
        crate::operation::update_email_identity_policy::UpdateEmailIdentityPolicyOutput {
            _request_id: self._request_id,
        }
    }
}
