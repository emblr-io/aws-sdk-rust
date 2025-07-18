// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetBackendAuthOutput {
    /// <p>The app ID.</p>
    pub app_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the backend environment.</p>
    pub backend_environment_name: ::std::option::Option<::std::string::String>,
    /// <p>If the request fails, this error is returned.</p>
    pub error: ::std::option::Option<::std::string::String>,
    /// <p>The resource configuration for authorization requests to the backend of your Amplify project.</p>
    pub resource_config: ::std::option::Option<crate::types::CreateBackendAuthResourceConfig>,
    /// <p>The name of this resource.</p>
    pub resource_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetBackendAuthOutput {
    /// <p>The app ID.</p>
    pub fn app_id(&self) -> ::std::option::Option<&str> {
        self.app_id.as_deref()
    }
    /// <p>The name of the backend environment.</p>
    pub fn backend_environment_name(&self) -> ::std::option::Option<&str> {
        self.backend_environment_name.as_deref()
    }
    /// <p>If the request fails, this error is returned.</p>
    pub fn error(&self) -> ::std::option::Option<&str> {
        self.error.as_deref()
    }
    /// <p>The resource configuration for authorization requests to the backend of your Amplify project.</p>
    pub fn resource_config(&self) -> ::std::option::Option<&crate::types::CreateBackendAuthResourceConfig> {
        self.resource_config.as_ref()
    }
    /// <p>The name of this resource.</p>
    pub fn resource_name(&self) -> ::std::option::Option<&str> {
        self.resource_name.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetBackendAuthOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetBackendAuthOutput {
    /// Creates a new builder-style object to manufacture [`GetBackendAuthOutput`](crate::operation::get_backend_auth::GetBackendAuthOutput).
    pub fn builder() -> crate::operation::get_backend_auth::builders::GetBackendAuthOutputBuilder {
        crate::operation::get_backend_auth::builders::GetBackendAuthOutputBuilder::default()
    }
}

/// A builder for [`GetBackendAuthOutput`](crate::operation::get_backend_auth::GetBackendAuthOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetBackendAuthOutputBuilder {
    pub(crate) app_id: ::std::option::Option<::std::string::String>,
    pub(crate) backend_environment_name: ::std::option::Option<::std::string::String>,
    pub(crate) error: ::std::option::Option<::std::string::String>,
    pub(crate) resource_config: ::std::option::Option<crate::types::CreateBackendAuthResourceConfig>,
    pub(crate) resource_name: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetBackendAuthOutputBuilder {
    /// <p>The app ID.</p>
    pub fn app_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.app_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The app ID.</p>
    pub fn set_app_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.app_id = input;
        self
    }
    /// <p>The app ID.</p>
    pub fn get_app_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.app_id
    }
    /// <p>The name of the backend environment.</p>
    pub fn backend_environment_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.backend_environment_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the backend environment.</p>
    pub fn set_backend_environment_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.backend_environment_name = input;
        self
    }
    /// <p>The name of the backend environment.</p>
    pub fn get_backend_environment_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.backend_environment_name
    }
    /// <p>If the request fails, this error is returned.</p>
    pub fn error(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.error = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the request fails, this error is returned.</p>
    pub fn set_error(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.error = input;
        self
    }
    /// <p>If the request fails, this error is returned.</p>
    pub fn get_error(&self) -> &::std::option::Option<::std::string::String> {
        &self.error
    }
    /// <p>The resource configuration for authorization requests to the backend of your Amplify project.</p>
    pub fn resource_config(mut self, input: crate::types::CreateBackendAuthResourceConfig) -> Self {
        self.resource_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>The resource configuration for authorization requests to the backend of your Amplify project.</p>
    pub fn set_resource_config(mut self, input: ::std::option::Option<crate::types::CreateBackendAuthResourceConfig>) -> Self {
        self.resource_config = input;
        self
    }
    /// <p>The resource configuration for authorization requests to the backend of your Amplify project.</p>
    pub fn get_resource_config(&self) -> &::std::option::Option<crate::types::CreateBackendAuthResourceConfig> {
        &self.resource_config
    }
    /// <p>The name of this resource.</p>
    pub fn resource_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of this resource.</p>
    pub fn set_resource_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_name = input;
        self
    }
    /// <p>The name of this resource.</p>
    pub fn get_resource_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_name
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetBackendAuthOutput`](crate::operation::get_backend_auth::GetBackendAuthOutput).
    pub fn build(self) -> crate::operation::get_backend_auth::GetBackendAuthOutput {
        crate::operation::get_backend_auth::GetBackendAuthOutput {
            app_id: self.app_id,
            backend_environment_name: self.backend_environment_name,
            error: self.error,
            resource_config: self.resource_config,
            resource_name: self.resource_name,
            _request_id: self._request_id,
        }
    }
}
