// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateSecurityConfigurationOutput {
    /// <p>The name of the security configuration.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The date and time the security configuration was created.</p>
    pub creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CreateSecurityConfigurationOutput {
    /// <p>The name of the security configuration.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The date and time the security configuration was created.</p>
    pub fn creation_date_time(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.creation_date_time.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateSecurityConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateSecurityConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`CreateSecurityConfigurationOutput`](crate::operation::create_security_configuration::CreateSecurityConfigurationOutput).
    pub fn builder() -> crate::operation::create_security_configuration::builders::CreateSecurityConfigurationOutputBuilder {
        crate::operation::create_security_configuration::builders::CreateSecurityConfigurationOutputBuilder::default()
    }
}

/// A builder for [`CreateSecurityConfigurationOutput`](crate::operation::create_security_configuration::CreateSecurityConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateSecurityConfigurationOutputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) creation_date_time: ::std::option::Option<::aws_smithy_types::DateTime>,
    _request_id: Option<String>,
}
impl CreateSecurityConfigurationOutputBuilder {
    /// <p>The name of the security configuration.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the security configuration.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the security configuration.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The date and time the security configuration was created.</p>
    /// This field is required.
    pub fn creation_date_time(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.creation_date_time = ::std::option::Option::Some(input);
        self
    }
    /// <p>The date and time the security configuration was created.</p>
    pub fn set_creation_date_time(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.creation_date_time = input;
        self
    }
    /// <p>The date and time the security configuration was created.</p>
    pub fn get_creation_date_time(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.creation_date_time
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateSecurityConfigurationOutput`](crate::operation::create_security_configuration::CreateSecurityConfigurationOutput).
    pub fn build(self) -> crate::operation::create_security_configuration::CreateSecurityConfigurationOutput {
        crate::operation::create_security_configuration::CreateSecurityConfigurationOutput {
            name: self.name,
            creation_date_time: self.creation_date_time,
            _request_id: self._request_id,
        }
    }
}
