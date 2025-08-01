// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteCisScanConfigurationOutput {
    /// <p>The ARN of the CIS scan configuration.</p>
    pub scan_configuration_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl DeleteCisScanConfigurationOutput {
    /// <p>The ARN of the CIS scan configuration.</p>
    pub fn scan_configuration_arn(&self) -> &str {
        use std::ops::Deref;
        self.scan_configuration_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for DeleteCisScanConfigurationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DeleteCisScanConfigurationOutput {
    /// Creates a new builder-style object to manufacture [`DeleteCisScanConfigurationOutput`](crate::operation::delete_cis_scan_configuration::DeleteCisScanConfigurationOutput).
    pub fn builder() -> crate::operation::delete_cis_scan_configuration::builders::DeleteCisScanConfigurationOutputBuilder {
        crate::operation::delete_cis_scan_configuration::builders::DeleteCisScanConfigurationOutputBuilder::default()
    }
}

/// A builder for [`DeleteCisScanConfigurationOutput`](crate::operation::delete_cis_scan_configuration::DeleteCisScanConfigurationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteCisScanConfigurationOutputBuilder {
    pub(crate) scan_configuration_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DeleteCisScanConfigurationOutputBuilder {
    /// <p>The ARN of the CIS scan configuration.</p>
    /// This field is required.
    pub fn scan_configuration_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.scan_configuration_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the CIS scan configuration.</p>
    pub fn set_scan_configuration_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.scan_configuration_arn = input;
        self
    }
    /// <p>The ARN of the CIS scan configuration.</p>
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
    /// Consumes the builder and constructs a [`DeleteCisScanConfigurationOutput`](crate::operation::delete_cis_scan_configuration::DeleteCisScanConfigurationOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`scan_configuration_arn`](crate::operation::delete_cis_scan_configuration::builders::DeleteCisScanConfigurationOutputBuilder::scan_configuration_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_cis_scan_configuration::DeleteCisScanConfigurationOutput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_cis_scan_configuration::DeleteCisScanConfigurationOutput {
            scan_configuration_arn: self.scan_configuration_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "scan_configuration_arn",
                    "scan_configuration_arn was not specified but it is required when building DeleteCisScanConfigurationOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
