// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCodeSecurityScanConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the created scan configuration.</p>
    pub scan_configuration_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl CreateCodeSecurityScanConfigurationOutput {
    /// <p>The Amazon Resource Name (ARN) of the created scan configuration.</p>
    pub fn scan_configuration_arn(&self) -> &str {
        use std::ops::Deref;
        self.scan_configuration_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateCodeSecurityScanConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateCodeSecurityScanConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`CreateCodeSecurityScanConfigurationOutput`](crate::operation::create_code_security_scan_configuration::CreateCodeSecurityScanConfigurationOutput).
    pub fn builder() -> crate::operation::create_code_security_scan_configuration::builders::CreateCodeSecurityScanConfigurationOutputBuilder {
        crate::operation::create_code_security_scan_configuration::builders::CreateCodeSecurityScanConfigurationOutputBuilder::default()
    }
}

/// A builder for [`CreateCodeSecurityScanConfigurationOutput`](crate::operation::create_code_security_scan_configuration::CreateCodeSecurityScanConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCodeSecurityScanConfigurationOutputBuilder {
    pub(crate) scan_configuration_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateCodeSecurityScanConfigurationOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the created scan configuration.</p>
    /// This field is required.
    pub fn scan_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scan_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the created scan configuration.</p>
    pub fn set_scan_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scan_configuration_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the created scan configuration.</p>
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
    /// Consumes the builder and constructs a [`CreateCodeSecurityScanConfigurationOutput`](crate::operation::create_code_security_scan_configuration::CreateCodeSecurityScanConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`scan_configuration_arn`](crate::operation::create_code_security_scan_configuration::builders::CreateCodeSecurityScanConfigurationOutputBuilder::scan_configuration_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_code_security_scan_configuration::CreateCodeSecurityScanConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::create_code_security_scan_configuration::CreateCodeSecurityScanConfigurationOutput {
                scan_configuration_arn: self.scan_configuration_arn.ok_or_else(|| {
                    ::aws_smithy_types::error::operation::BuildError::missing_field(
                        "scan_configuration_arn",
                        "scan_configuration_arn was not specified but it is required when building CreateCodeSecurityScanConfigurationOutput",
                    )
                })?,
                _request_id: self._request_id,
            },
        )
    }
}
