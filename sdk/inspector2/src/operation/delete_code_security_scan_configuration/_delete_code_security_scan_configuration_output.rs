// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCodeSecurityScanConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the deleted scan configuration.</p>
    pub scan_configuration_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteCodeSecurityScanConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the deleted scan configuration.</p>
    pub fn scan_configuration_arn(&self) -> ::std::option::Option<&str> {
        self.scan_configuration_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteCodeSecurityScanConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteCodeSecurityScanConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteCodeSecurityScanConfigurationOutput`](crate::operation::delete_code_security_scan_configuration::DeleteCodeSecurityScanConfigurationOutput).
    pub fn builder() -> crate::operation::delete_code_security_scan_configuration::builders::DeleteCodeSecurityScanConfigurationOutputBuilder {
        crate::operation::delete_code_security_scan_configuration::builders::DeleteCodeSecurityScanConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteCodeSecurityScanConfigurationOutput`](crate::operation::delete_code_security_scan_configuration::DeleteCodeSecurityScanConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCodeSecurityScanConfigurationOutputBuilder {
    pub(crate) scan_configuration_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteCodeSecurityScanConfigurationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the deleted scan configuration.</p>
    pub fn scan_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scan_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the deleted scan configuration.</p>
    pub fn set_scan_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scan_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the deleted scan configuration.</p>
    pub fn get_scan_configuration_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.scan_configuration_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DeleteCodeSecurityScanConfigurationOutput`](crate::operation::delete_code_security_scan_configuration::DeleteCodeSecurityScanConfigurationOutput).
    pub fn build(self) -> crate::operation::delete_code_security_scan_configuration::DeleteCodeSecurityScanConfigurationOutput {
        crate::operation::delete_code_security_scan_configuration::DeleteCodeSecurityScanConfigurationOutput {
            scan_configuration_arn: self.scan_configuration_arn,
            _request_id: self._request_id,
        }
    }
}
