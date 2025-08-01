// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRegistryPolicyOutput {
    /// <p>The registry ID associated with the request.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The JSON policy text for your registry.</p>
    pub policy_text: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutRegistryPolicyOutput {
    /// <p>The registry ID associated with the request.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The JSON policy text for your registry.</p>
    pub fn policy_text(&self) -> ::std::option::Option<&str> {
        self.policy_text.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for PutRegistryPolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutRegistryPolicyOutput {
    /// Creates a new builder-style object to manufacture [`PutRegistryPolicyOutput`](crate::operation::put_registry_policy::PutRegistryPolicyOutput).
    pub fn builder() -> crate::operation::put_registry_policy::builders::PutRegistryPolicyOutputBuilder {
        crate::operation::put_registry_policy::builders::PutRegistryPolicyOutputBuilder::default()
    }
}

/// A builder for [`PutRegistryPolicyOutput`](crate::operation::put_registry_policy::PutRegistryPolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRegistryPolicyOutputBuilder {
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) policy_text: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutRegistryPolicyOutputBuilder {
    /// <p>The registry ID associated with the request.</p>
    pub fn registry_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.registry_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The registry ID associated with the request.</p>
    pub fn set_registry_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.registry_id = input;
        self
    }
    /// <p>The registry ID associated with the request.</p>
    pub fn get_registry_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.registry_id
    }
    /// <p>The JSON policy text for your registry.</p>
    pub fn policy_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.policy_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON policy text for your registry.</p>
    pub fn set_policy_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.policy_text = input;
        self
    }
    /// <p>The JSON policy text for your registry.</p>
    pub fn get_policy_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.policy_text
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutRegistryPolicyOutput`](crate::operation::put_registry_policy::PutRegistryPolicyOutput).
    pub fn build(self) -> crate::operation::put_registry_policy::PutRegistryPolicyOutput {
        crate::operation::put_registry_policy::PutRegistryPolicyOutput {
            registry_id: self.registry_id,
            policy_text: self.policy_text,
            _request_id: self._request_id,
        }
    }
}
