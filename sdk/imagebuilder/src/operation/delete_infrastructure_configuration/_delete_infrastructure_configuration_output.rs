// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteInfrastructureConfigurationOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that was deleted.</p>
    pub infrastructure_configuration_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteInfrastructureConfigurationOutput {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that was deleted.</p>
    pub fn infrastructure_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.infrastructure_configuration_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteInfrastructureConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteInfrastructureConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteInfrastructureConfigurationOutput`](crate::operation::delete_infrastructure_configuration::DeleteInfrastructureConfigurationOutput).
    pub fn builder() -> crate::operation::delete_infrastructure_configuration::builders::DeleteInfrastructureConfigurationOutputBuilder {
        crate::operation::delete_infrastructure_configuration::builders::DeleteInfrastructureConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteInfrastructureConfigurationOutput`](crate::operation::delete_infrastructure_configuration::DeleteInfrastructureConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteInfrastructureConfigurationOutputBuilder {
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) infrastructure_configuration_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteInfrastructureConfigurationOutputBuilder {
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The request ID that uniquely identifies this request.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that was deleted.</p>
    pub fn infrastructure_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.infrastructure_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that was deleted.</p>
    pub fn set_infrastructure_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.infrastructure_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the infrastructure configuration that was deleted.</p>
    pub fn get_infrastructure_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.infrastructure_configuration_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteInfrastructureConfigurationOutput`](crate::operation::delete_infrastructure_configuration::DeleteInfrastructureConfigurationOutput).
    pub fn build(self) -> crate::operation::delete_infrastructure_configuration::DeleteInfrastructureConfigurationOutput {
        crate::operation::delete_infrastructure_configuration::DeleteInfrastructureConfigurationOutput {
            request_id: self.request_id,
            infrastructure_configuration_arn: self.infrastructure_configuration_arn,
            _request_id: self._request_id,
        }
    }
}
