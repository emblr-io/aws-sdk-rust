// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSecurityPolicyOutput {
    /// <p>Details about the created security policy.</p>
    pub security_policy_detail: ::std::option::Option<crate::types::SecurityPolicyDetail>,
    _request_id: Option<String>,
}
impl CreateSecurityPolicyOutput {
    /// <p>Details about the created security policy.</p>
    pub fn security_policy_detail(&self) -> ::std::option::Option<&crate::types::SecurityPolicyDetail> {
        self.security_policy_detail.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateSecurityPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSecurityPolicyOutput {
    /// Creates a new builder-style object to manufacture [`CreateSecurityPolicyOutput`](crate::operation::create_security_policy::CreateSecurityPolicyOutput).
    pub fn builder() -> crate::operation::create_security_policy::builders::CreateSecurityPolicyOutputBuilder {
        crate::operation::create_security_policy::builders::CreateSecurityPolicyOutputBuilder::default()
    }
}

/// A builder for [`CreateSecurityPolicyOutput`](crate::operation::create_security_policy::CreateSecurityPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSecurityPolicyOutputBuilder {
    pub(crate) security_policy_detail: ::std::option::Option<crate::types::SecurityPolicyDetail>,
    _request_id: Option<String>,
}
impl CreateSecurityPolicyOutputBuilder {
    /// <p>Details about the created security policy.</p>
    pub fn security_policy_detail(mut self, input: crate::types::SecurityPolicyDetail) -> Self {
        self.security_policy_detail = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the created security policy.</p>
    pub fn set_security_policy_detail(mut self, input: ::std::option::Option<crate::types::SecurityPolicyDetail>) -> Self {
        self.security_policy_detail = input;
        self
    }
    /// <p>Details about the created security policy.</p>
    pub fn get_security_policy_detail(&self) -> &::std::option::Option<crate::types::SecurityPolicyDetail> {
        &self.security_policy_detail
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSecurityPolicyOutput`](crate::operation::create_security_policy::CreateSecurityPolicyOutput).
    pub fn build(self) -> crate::operation::create_security_policy::CreateSecurityPolicyOutput {
        crate::operation::create_security_policy::CreateSecurityPolicyOutput {
            security_policy_detail: self.security_policy_detail,
            _request_id: self._request_id,
        }
    }
}
