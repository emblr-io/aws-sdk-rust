// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutLifecyclePolicyOutput {
    /// <p>The registry ID associated with the request.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The repository name associated with the request.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The JSON repository policy text.</p>
    pub lifecycle_policy_text: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutLifecyclePolicyOutput {
    /// <p>The registry ID associated with the request.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The repository name associated with the request.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The JSON repository policy text.</p>
    pub fn lifecycle_policy_text(&self) -> ::std::option::Option<&str> {
        self.lifecycle_policy_text.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for PutLifecyclePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl PutLifecyclePolicyOutput {
    /// Creates a new builder-style object to manufacture [`PutLifecyclePolicyOutput`](crate::operation::put_lifecycle_policy::PutLifecyclePolicyOutput).
    pub fn builder() -> crate::operation::put_lifecycle_policy::builders::PutLifecyclePolicyOutputBuilder {
        crate::operation::put_lifecycle_policy::builders::PutLifecyclePolicyOutputBuilder::default()
    }
}

/// A builder for [`PutLifecyclePolicyOutput`](crate::operation::put_lifecycle_policy::PutLifecyclePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutLifecyclePolicyOutputBuilder {
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_policy_text: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl PutLifecyclePolicyOutputBuilder {
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
    /// <p>The repository name associated with the request.</p>
    pub fn repository_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.repository_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The repository name associated with the request.</p>
    pub fn set_repository_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.repository_name = input;
        self
    }
    /// <p>The repository name associated with the request.</p>
    pub fn get_repository_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.repository_name
    }
    /// <p>The JSON repository policy text.</p>
    pub fn lifecycle_policy_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_policy_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON repository policy text.</p>
    pub fn set_lifecycle_policy_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_policy_text = input;
        self
    }
    /// <p>The JSON repository policy text.</p>
    pub fn get_lifecycle_policy_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_policy_text
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`PutLifecyclePolicyOutput`](crate::operation::put_lifecycle_policy::PutLifecyclePolicyOutput).
    pub fn build(self) -> crate::operation::put_lifecycle_policy::PutLifecyclePolicyOutput {
        crate::operation::put_lifecycle_policy::PutLifecyclePolicyOutput {
            registry_id: self.registry_id,
            repository_name: self.repository_name,
            lifecycle_policy_text: self.lifecycle_policy_text,
            _request_id: self._request_id,
        }
    }
}
