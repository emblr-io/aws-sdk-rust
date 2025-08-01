// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRuntimeLogConfigurationOutput {
    /// <p>The id for a managed thing.</p>
    pub managed_thing_id: ::std::option::Option<::std::string::String>,
    /// <p>The runtime log configuration for a managed thing.</p>
    pub runtime_log_configurations: ::std::option::Option<crate::types::RuntimeLogConfigurations>,
    _request_id: Option<String>,
}
impl GetRuntimeLogConfigurationOutput {
    /// <p>The id for a managed thing.</p>
    pub fn managed_thing_id(&self) -> ::std::option::Option<&str> {
        self.managed_thing_id.as_deref()
    }
    /// <p>The runtime log configuration for a managed thing.</p>
    pub fn runtime_log_configurations(&self) -> ::std::option::Option<&crate::types::RuntimeLogConfigurations> {
        self.runtime_log_configurations.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRuntimeLogConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRuntimeLogConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetRuntimeLogConfigurationOutput`](crate::operation::get_runtime_log_configuration::GetRuntimeLogConfigurationOutput).
    pub fn builder() -> crate::operation::get_runtime_log_configuration::builders::GetRuntimeLogConfigurationOutputBuilder {
        crate::operation::get_runtime_log_configuration::builders::GetRuntimeLogConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetRuntimeLogConfigurationOutput`](crate::operation::get_runtime_log_configuration::GetRuntimeLogConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRuntimeLogConfigurationOutputBuilder {
    pub(crate) managed_thing_id: ::std::option::Option<::std::string::String>,
    pub(crate) runtime_log_configurations: ::std::option::Option<crate::types::RuntimeLogConfigurations>,
    _request_id: Option<String>,
}
impl GetRuntimeLogConfigurationOutputBuilder {
    /// <p>The id for a managed thing.</p>
    pub fn managed_thing_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.managed_thing_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The id for a managed thing.</p>
    pub fn set_managed_thing_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.managed_thing_id = input;
        self
    }
    /// <p>The id for a managed thing.</p>
    pub fn get_managed_thing_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.managed_thing_id
    }
    /// <p>The runtime log configuration for a managed thing.</p>
    pub fn runtime_log_configurations(mut self, input: crate::types::RuntimeLogConfigurations) -> Self {
        self.runtime_log_configurations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The runtime log configuration for a managed thing.</p>
    pub fn set_runtime_log_configurations(mut self, input: ::std::option::Option<crate::types::RuntimeLogConfigurations>) -> Self {
        self.runtime_log_configurations = input;
        self
    }
    /// <p>The runtime log configuration for a managed thing.</p>
    pub fn get_runtime_log_configurations(&self) -> &::std::option::Option<crate::types::RuntimeLogConfigurations> {
        &self.runtime_log_configurations
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRuntimeLogConfigurationOutput`](crate::operation::get_runtime_log_configuration::GetRuntimeLogConfigurationOutput).
    pub fn build(self) -> crate::operation::get_runtime_log_configuration::GetRuntimeLogConfigurationOutput {
        crate::operation::get_runtime_log_configuration::GetRuntimeLogConfigurationOutput {
            managed_thing_id: self.managed_thing_id,
            runtime_log_configurations: self.runtime_log_configurations,
            _request_id: self._request_id,
        }
    }
}
