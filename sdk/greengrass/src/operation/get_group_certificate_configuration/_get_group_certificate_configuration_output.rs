// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetGroupCertificateConfigurationOutput {
    /// The amount of time remaining before the certificate authority expires, in milliseconds.
    pub certificate_authority_expiry_in_milliseconds: ::std::option::Option<::std::string::String>,
    /// The amount of time remaining before the certificate expires, in milliseconds.
    pub certificate_expiry_in_milliseconds: ::std::option::Option<::std::string::String>,
    /// The ID of the group certificate configuration.
    pub group_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetGroupCertificateConfigurationOutput {
    /// The amount of time remaining before the certificate authority expires, in milliseconds.
    pub fn certificate_authority_expiry_in_milliseconds(&self) -> ::std::option::Option<&str> {
        self.certificate_authority_expiry_in_milliseconds.as_deref()
    }
    /// The amount of time remaining before the certificate expires, in milliseconds.
    pub fn certificate_expiry_in_milliseconds(&self) -> ::std::option::Option<&str> {
        self.certificate_expiry_in_milliseconds.as_deref()
    }
    /// The ID of the group certificate configuration.
    pub fn group_id(&self) -> ::std::option::Option<&str> {
        self.group_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetGroupCertificateConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetGroupCertificateConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`GetGroupCertificateConfigurationOutput`](crate::operation::get_group_certificate_configuration::GetGroupCertificateConfigurationOutput).
    pub fn builder() -> crate::operation::get_group_certificate_configuration::builders::GetGroupCertificateConfigurationOutputBuilder {
        crate::operation::get_group_certificate_configuration::builders::GetGroupCertificateConfigurationOutputBuilder::default()
    }
}

/// A builder for [`GetGroupCertificateConfigurationOutput`](crate::operation::get_group_certificate_configuration::GetGroupCertificateConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetGroupCertificateConfigurationOutputBuilder {
    pub(crate) certificate_authority_expiry_in_milliseconds: ::std::option::Option<::std::string::String>,
    pub(crate) certificate_expiry_in_milliseconds: ::std::option::Option<::std::string::String>,
    pub(crate) group_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetGroupCertificateConfigurationOutputBuilder {
    /// The amount of time remaining before the certificate authority expires, in milliseconds.
    pub fn certificate_authority_expiry_in_milliseconds(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_authority_expiry_in_milliseconds = ::std::option::Option::Some(input.into());
        self
    }
    /// The amount of time remaining before the certificate authority expires, in milliseconds.
    pub fn set_certificate_authority_expiry_in_milliseconds(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_authority_expiry_in_milliseconds = input;
        self
    }
    /// The amount of time remaining before the certificate authority expires, in milliseconds.
    pub fn get_certificate_authority_expiry_in_milliseconds(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_authority_expiry_in_milliseconds
    }
    /// The amount of time remaining before the certificate expires, in milliseconds.
    pub fn certificate_expiry_in_milliseconds(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.certificate_expiry_in_milliseconds = ::std::option::Option::Some(input.into());
        self
    }
    /// The amount of time remaining before the certificate expires, in milliseconds.
    pub fn set_certificate_expiry_in_milliseconds(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.certificate_expiry_in_milliseconds = input;
        self
    }
    /// The amount of time remaining before the certificate expires, in milliseconds.
    pub fn get_certificate_expiry_in_milliseconds(&self) -> &::std::option::Option<::std::string::String> {
        &self.certificate_expiry_in_milliseconds
    }
    /// The ID of the group certificate configuration.
    pub fn group_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group_id = ::std::option::Option::Some(input.into());
        self
    }
    /// The ID of the group certificate configuration.
    pub fn set_group_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group_id = input;
        self
    }
    /// The ID of the group certificate configuration.
    pub fn get_group_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.group_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetGroupCertificateConfigurationOutput`](crate::operation::get_group_certificate_configuration::GetGroupCertificateConfigurationOutput).
    pub fn build(self) -> crate::operation::get_group_certificate_configuration::GetGroupCertificateConfigurationOutput {
        crate::operation::get_group_certificate_configuration::GetGroupCertificateConfigurationOutput {
            certificate_authority_expiry_in_milliseconds: self.certificate_authority_expiry_in_milliseconds,
            certificate_expiry_in_milliseconds: self.certificate_expiry_in_milliseconds,
            group_id: self.group_id,
            _request_id: self._request_id,
        }
    }
}
