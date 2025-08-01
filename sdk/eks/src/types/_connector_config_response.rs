// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The full description of your connected cluster.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ConnectorConfigResponse {
    /// <p>A unique ID associated with the cluster for registration purposes.</p>
    pub activation_id: ::std::option::Option<::std::string::String>,
    /// <p>A unique code associated with the cluster for registration purposes.</p>
    pub activation_code: ::std::option::Option<::std::string::String>,
    /// <p>The expiration time of the connected cluster. The cluster's YAML file must be applied through the native provider.</p>
    pub activation_expiry: ::std::option::Option<::aws_smithy_types::DateTime>,
    /// <p>The cluster's cloud service provider.</p>
    pub provider: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the role to communicate with services from the connected Kubernetes cluster.</p>
    pub role_arn: ::std::option::Option<::std::string::String>,
}
impl ConnectorConfigResponse {
    /// <p>A unique ID associated with the cluster for registration purposes.</p>
    pub fn activation_id(&self) -> ::std::option::Option<&str> {
        self.activation_id.as_deref()
    }
    /// <p>A unique code associated with the cluster for registration purposes.</p>
    pub fn activation_code(&self) -> ::std::option::Option<&str> {
        self.activation_code.as_deref()
    }
    /// <p>The expiration time of the connected cluster. The cluster's YAML file must be applied through the native provider.</p>
    pub fn activation_expiry(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.activation_expiry.as_ref()
    }
    /// <p>The cluster's cloud service provider.</p>
    pub fn provider(&self) -> ::std::option::Option<&str> {
        self.provider.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the role to communicate with services from the connected Kubernetes cluster.</p>
    pub fn role_arn(&self) -> ::std::option::Option<&str> {
        self.role_arn.as_deref()
    }
}
impl ConnectorConfigResponse {
    /// Creates a new builder-style object to manufacture [`ConnectorConfigResponse`](crate::types::ConnectorConfigResponse).
    pub fn builder() -> crate::types::builders::ConnectorConfigResponseBuilder {
        crate::types::builders::ConnectorConfigResponseBuilder::default()
    }
}

/// A builder for [`ConnectorConfigResponse`](crate::types::ConnectorConfigResponse).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ConnectorConfigResponseBuilder {
    pub(crate) activation_id: ::std::option::Option<::std::string::String>,
    pub(crate) activation_code: ::std::option::Option<::std::string::String>,
    pub(crate) activation_expiry: ::std::option::Option<::aws_smithy_types::DateTime>,
    pub(crate) provider: ::std::option::Option<::std::string::String>,
    pub(crate) role_arn: ::std::option::Option<::std::string::String>,
}
impl ConnectorConfigResponseBuilder {
    /// <p>A unique ID associated with the cluster for registration purposes.</p>
    pub fn activation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.activation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique ID associated with the cluster for registration purposes.</p>
    pub fn set_activation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.activation_id = input;
        self
    }
    /// <p>A unique ID associated with the cluster for registration purposes.</p>
    pub fn get_activation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.activation_id
    }
    /// <p>A unique code associated with the cluster for registration purposes.</p>
    pub fn activation_code(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.activation_code = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique code associated with the cluster for registration purposes.</p>
    pub fn set_activation_code(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.activation_code = input;
        self
    }
    /// <p>A unique code associated with the cluster for registration purposes.</p>
    pub fn get_activation_code(&self) -> &::std::option::Option<::std::string::String> {
        &self.activation_code
    }
    /// <p>The expiration time of the connected cluster. The cluster's YAML file must be applied through the native provider.</p>
    pub fn activation_expiry(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.activation_expiry = ::std::option::Option::Some(input);
        self
    }
    /// <p>The expiration time of the connected cluster. The cluster's YAML file must be applied through the native provider.</p>
    pub fn set_activation_expiry(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.activation_expiry = input;
        self
    }
    /// <p>The expiration time of the connected cluster. The cluster's YAML file must be applied through the native provider.</p>
    pub fn get_activation_expiry(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.activation_expiry
    }
    /// <p>The cluster's cloud service provider.</p>
    pub fn provider(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.provider = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster's cloud service provider.</p>
    pub fn set_provider(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.provider = input;
        self
    }
    /// <p>The cluster's cloud service provider.</p>
    pub fn get_provider(&self) -> &::std::option::Option<::std::string::String> {
        &self.provider
    }
    /// <p>The Amazon Resource Name (ARN) of the role to communicate with services from the connected Kubernetes cluster.</p>
    pub fn role_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.role_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role to communicate with services from the connected Kubernetes cluster.</p>
    pub fn set_role_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.role_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the role to communicate with services from the connected Kubernetes cluster.</p>
    pub fn get_role_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.role_arn
    }
    /// Consumes the builder and constructs a [`ConnectorConfigResponse`](crate::types::ConnectorConfigResponse).
    pub fn build(self) -> crate::types::ConnectorConfigResponse {
        crate::types::ConnectorConfigResponse {
            activation_id: self.activation_id,
            activation_code: self.activation_code,
            activation_expiry: self.activation_expiry,
            provider: self.provider,
            role_arn: self.role_arn,
        }
    }
}
