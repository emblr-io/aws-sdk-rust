// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetLicenseManagerReportGeneratorInput {
    /// <p>Amazon Resource Name (ARN) of the report generator.</p>
    pub license_manager_report_generator_arn: ::std::option::Option<::std::string::String>,
}
impl GetLicenseManagerReportGeneratorInput {
    /// <p>Amazon Resource Name (ARN) of the report generator.</p>
    pub fn license_manager_report_generator_arn(&self) -> ::std::option::Option<&str> {
        self.license_manager_report_generator_arn.as_deref()
    }
}
impl GetLicenseManagerReportGeneratorInput {
    /// Creates a new builder-style object to manufacture [`GetLicenseManagerReportGeneratorInput`](crate::operation::get_license_manager_report_generator::GetLicenseManagerReportGeneratorInput).
    pub fn builder() -> crate::operation::get_license_manager_report_generator::builders::GetLicenseManagerReportGeneratorInputBuilder {
        crate::operation::get_license_manager_report_generator::builders::GetLicenseManagerReportGeneratorInputBuilder::default()
    }
}

/// A builder for [`GetLicenseManagerReportGeneratorInput`](crate::operation::get_license_manager_report_generator::GetLicenseManagerReportGeneratorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetLicenseManagerReportGeneratorInputBuilder {
    pub(crate) license_manager_report_generator_arn: ::std::option::Option<::std::string::String>,
}
impl GetLicenseManagerReportGeneratorInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the report generator.</p>
    /// This field is required.
    pub fn license_manager_report_generator_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_manager_report_generator_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the report generator.</p>
    pub fn set_license_manager_report_generator_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_manager_report_generator_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the report generator.</p>
    pub fn get_license_manager_report_generator_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_manager_report_generator_arn
    }
    /// Consumes the builder and constructs a [`GetLicenseManagerReportGeneratorInput`](crate::operation::get_license_manager_report_generator::GetLicenseManagerReportGeneratorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::get_license_manager_report_generator::GetLicenseManagerReportGeneratorInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::get_license_manager_report_generator::GetLicenseManagerReportGeneratorInput {
                license_manager_report_generator_arn: self.license_manager_report_generator_arn,
            },
        )
    }
}
