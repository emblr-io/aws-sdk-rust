// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeSecurityPolicyOutput {
    /// <p>An array containing the properties of the security policy.</p>
    pub security_policy: ::std::option::Option<crate::types::DescribedSecurityPolicy>,
    _request_id: Option<String>,
}
impl DescribeSecurityPolicyOutput {
    /// <p>An array containing the properties of the security policy.</p>
    pub fn security_policy(&self) -> ::std::option::Option<&crate::types::DescribedSecurityPolicy> {
        self.security_policy.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeSecurityPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeSecurityPolicyOutput {
    /// Creates a new builder-style object to manufacture [`DescribeSecurityPolicyOutput`](crate::operation::describe_security_policy::DescribeSecurityPolicyOutput).
    pub fn builder() -> crate::operation::describe_security_policy::builders::DescribeSecurityPolicyOutputBuilder {
        crate::operation::describe_security_policy::builders::DescribeSecurityPolicyOutputBuilder::default()
    }
}

/// A builder for [`DescribeSecurityPolicyOutput`](crate::operation::describe_security_policy::DescribeSecurityPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeSecurityPolicyOutputBuilder {
    pub(crate) security_policy: ::std::option::Option<crate::types::DescribedSecurityPolicy>,
    _request_id: Option<String>,
}
impl DescribeSecurityPolicyOutputBuilder {
    /// <p>An array containing the properties of the security policy.</p>
    /// This field is required.
    pub fn security_policy(mut self, input: crate::types::DescribedSecurityPolicy) -> Self {
        self.security_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>An array containing the properties of the security policy.</p>
    pub fn set_security_policy(mut self, input: ::std::option::Option<crate::types::DescribedSecurityPolicy>) -> Self {
        self.security_policy = input;
        self
    }
    /// <p>An array containing the properties of the security policy.</p>
    pub fn get_security_policy(&self) -> &::std::option::Option<crate::types::DescribedSecurityPolicy> {
        &self.security_policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeSecurityPolicyOutput`](crate::operation::describe_security_policy::DescribeSecurityPolicyOutput).
    pub fn build(self) -> crate::operation::describe_security_policy::DescribeSecurityPolicyOutput {
        crate::operation::describe_security_policy::DescribeSecurityPolicyOutput {
            security_policy: self.security_policy,
            _request_id: self._request_id,
        }
    }
}
