// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetKeyPolicyOutput {
    /// <p>A key policy document in JSON format.</p>
    pub policy: ::std::option::Option<::std::string::String>,
    /// <p>The name of the key policy. The only valid value is <code>default</code>.</p>
    pub policy_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetKeyPolicyOutput {
    /// <p>A key policy document in JSON format.</p>
    pub fn policy(&self) -> ::std::option::Option<&str> {
        self.policy.as_deref()
    }
    /// <p>The name of the key policy. The only valid value is <code>default</code>.</p>
    pub fn policy_name(&self) -> ::std::option::Option<&str> {
        self.policy_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetKeyPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetKeyPolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetKeyPolicyOutput`](crate::operation::get_key_policy::GetKeyPolicyOutput).
    pub fn builder() -> crate::operation::get_key_policy::builders::GetKeyPolicyOutputBuilder {
        crate::operation::get_key_policy::builders::GetKeyPolicyOutputBuilder::default()
    }
}

/// A builder for [`GetKeyPolicyOutput`](crate::operation::get_key_policy::GetKeyPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetKeyPolicyOutputBuilder {
    pub(crate) policy: ::std::option::Option<::std::string::String>,
    pub(crate) policy_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetKeyPolicyOutputBuilder {
    /// <p>A key policy document in JSON format.</p>
    pub fn policy(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A key policy document in JSON format.</p>
    pub fn set_policy(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy = input;
        self
    }
    /// <p>A key policy document in JSON format.</p>
    pub fn get_policy(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy
    }
    /// <p>The name of the key policy. The only valid value is <code>default</code>.</p>
    pub fn policy_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the key policy. The only valid value is <code>default</code>.</p>
    pub fn set_policy_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_name = input;
        self
    }
    /// <p>The name of the key policy. The only valid value is <code>default</code>.</p>
    pub fn get_policy_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetKeyPolicyOutput`](crate::operation::get_key_policy::GetKeyPolicyOutput).
    pub fn build(self) -> crate::operation::get_key_policy::GetKeyPolicyOutput {
        crate::operation::get_key_policy::GetKeyPolicyOutput {
            policy: self.policy,
            policy_name: self.policy_name,
            _request_id: self._request_id,
        }
    }
}
