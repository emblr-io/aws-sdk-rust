// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutPolicyOutput {
    /// A policy configures behavior that you allow or disallow for your account. For information about MediaConvert policies, see the user guide at http://docs.aws.amazon.com/mediaconvert/latest/ug/what-is.html
    pub policy: ::std::option::Option<crate::types::Policy>,
    _request_id: Option<String>,
}
impl PutPolicyOutput {
    /// A policy configures behavior that you allow or disallow for your account. For information about MediaConvert policies, see the user guide at http://docs.aws.amazon.com/mediaconvert/latest/ug/what-is.html
    pub fn policy(&self) -> ::std::option::Option<&crate::types::Policy> {
        self.policy.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for PutPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutPolicyOutput {
    /// Creates a new builder-style object to manufacture [`PutPolicyOutput`](crate::operation::put_policy::PutPolicyOutput).
    pub fn builder() -> crate::operation::put_policy::builders::PutPolicyOutputBuilder {
        crate::operation::put_policy::builders::PutPolicyOutputBuilder::default()
    }
}

/// A builder for [`PutPolicyOutput`](crate::operation::put_policy::PutPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutPolicyOutputBuilder {
    pub(crate) policy: ::std::option::Option<crate::types::Policy>,
    _request_id: Option<String>,
}
impl PutPolicyOutputBuilder {
    /// A policy configures behavior that you allow or disallow for your account. For information about MediaConvert policies, see the user guide at http://docs.aws.amazon.com/mediaconvert/latest/ug/what-is.html
    pub fn policy(mut self, input: crate::types::Policy) -> Self {
        self.policy = ::std::option::Option::Some(input);
        self
    }
    /// A policy configures behavior that you allow or disallow for your account. For information about MediaConvert policies, see the user guide at http://docs.aws.amazon.com/mediaconvert/latest/ug/what-is.html
    pub fn set_policy(mut self, input: ::std::option::Option<crate::types::Policy>) -> Self {
        self.policy = input;
        self
    }
    /// A policy configures behavior that you allow or disallow for your account. For information about MediaConvert policies, see the user guide at http://docs.aws.amazon.com/mediaconvert/latest/ug/what-is.html
    pub fn get_policy(&self) -> &::std::option::Option<crate::types::Policy> {
        &self.policy
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutPolicyOutput`](crate::operation::put_policy::PutPolicyOutput).
    pub fn build(self) -> crate::operation::put_policy::PutPolicyOutput {
        crate::operation::put_policy::PutPolicyOutput {
            policy: self.policy,
            _request_id: self._request_id,
        }
    }
}
