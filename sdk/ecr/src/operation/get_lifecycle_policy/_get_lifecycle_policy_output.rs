// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLifecyclePolicyOutput {
    /// <p>The registry ID associated with the request.</p>
    pub registry_id: ::std::option::Option<::std::string::String>,
    /// <p>The repository name associated with the request.</p>
    pub repository_name: ::std::option::Option<::std::string::String>,
    /// <p>The JSON lifecycle policy text.</p>
    pub lifecycle_policy_text: ::std::option::Option<::std::string::String>,
    /// <p>The time stamp of the last time that the lifecycle policy was run.</p>
    pub last_evaluated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetLifecyclePolicyOutput {
    /// <p>The registry ID associated with the request.</p>
    pub fn registry_id(&self) -> ::std::option::Option<&str> {
        self.registry_id.as_deref()
    }
    /// <p>The repository name associated with the request.</p>
    pub fn repository_name(&self) -> ::std::option::Option<&str> {
        self.repository_name.as_deref()
    }
    /// <p>The JSON lifecycle policy text.</p>
    pub fn lifecycle_policy_text(&self) -> ::std::option::Option<&str> {
        self.lifecycle_policy_text.as_deref()
    }
    /// <p>The time stamp of the last time that the lifecycle policy was run.</p>
    pub fn last_evaluated_at(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_evaluated_at.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetLifecyclePolicyOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetLifecyclePolicyOutput {
    /// Creates a new builder-style object to manufacture [`GetLifecyclePolicyOutput`](crate::operation::get_lifecycle_policy::GetLifecyclePolicyOutput).
    pub fn builder() -> crate::operation::get_lifecycle_policy::builders::GetLifecyclePolicyOutputBuilder {
        crate::operation::get_lifecycle_policy::builders::GetLifecyclePolicyOutputBuilder::default()
    }
}

/// A builder for [`GetLifecyclePolicyOutput`](crate::operation::get_lifecycle_policy::GetLifecyclePolicyOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLifecyclePolicyOutputBuilder {
    pub(crate) registry_id: ::std::option::Option<::std::string::String>,
    pub(crate) repository_name: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_policy_text: ::std::option::Option<::std::string::String>,
    pub(crate) last_evaluated_at: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl GetLifecyclePolicyOutputBuilder {
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
    /// <p>The JSON lifecycle policy text.</p>
    pub fn lifecycle_policy_text(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.lifecycle_policy_text = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The JSON lifecycle policy text.</p>
    pub fn set_lifecycle_policy_text(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.lifecycle_policy_text = input;
        self
    }
    /// <p>The JSON lifecycle policy text.</p>
    pub fn get_lifecycle_policy_text(&self) -> &::std::option::Option<::std::string::String> {
        &self.lifecycle_policy_text
    }
    /// <p>The time stamp of the last time that the lifecycle policy was run.</p>
    pub fn last_evaluated_at(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_evaluated_at = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time stamp of the last time that the lifecycle policy was run.</p>
    pub fn set_last_evaluated_at(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_evaluated_at = input;
        self
    }
    /// <p>The time stamp of the last time that the lifecycle policy was run.</p>
    pub fn get_last_evaluated_at(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_evaluated_at
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetLifecyclePolicyOutput`](crate::operation::get_lifecycle_policy::GetLifecyclePolicyOutput).
    pub fn build(self) -> crate::operation::get_lifecycle_policy::GetLifecyclePolicyOutput {
        crate::operation::get_lifecycle_policy::GetLifecyclePolicyOutput {
            registry_id: self.registry_id,
            repository_name: self.repository_name,
            lifecycle_policy_text: self.lifecycle_policy_text,
            last_evaluated_at: self.last_evaluated_at,
            _request_id: self._request_id,
        }
    }
}
