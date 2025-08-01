// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLicenseManagerReportGeneratorInput {
    /// <p>Amazon Resource Name (ARN) of the report generator to update.</p>
    pub license_manager_report_generator_arn: ::std::option::Option<::std::string::String>,
    /// <p>Name of the report generator.</p>
    pub report_generator_name: ::std::option::Option<::std::string::String>,
    /// <p>Type of reports to generate. The following report types are supported:</p>
    /// <ul>
    /// <li>
    /// <p>License configuration report - Reports the number and details of consumed licenses for a license configuration.</p></li>
    /// <li>
    /// <p>Resource report - Reports the tracked licenses and resource consumption for a license configuration.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<::std::vec::Vec<crate::types::ReportType>>,
    /// <p>The report context.</p>
    pub report_context: ::std::option::Option<crate::types::ReportContext>,
    /// <p>Frequency by which reports are generated.</p>
    pub report_frequency: ::std::option::Option<crate::types::ReportFrequency>,
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub client_token: ::std::option::Option<::std::string::String>,
    /// <p>Description of the report generator.</p>
    pub description: ::std::option::Option<::std::string::String>,
}
impl UpdateLicenseManagerReportGeneratorInput {
    /// <p>Amazon Resource Name (ARN) of the report generator to update.</p>
    pub fn license_manager_report_generator_arn(&self) -> ::std::option::Option<&str> {
        self.license_manager_report_generator_arn.as_deref()
    }
    /// <p>Name of the report generator.</p>
    pub fn report_generator_name(&self) -> ::std::option::Option<&str> {
        self.report_generator_name.as_deref()
    }
    /// <p>Type of reports to generate. The following report types are supported:</p>
    /// <ul>
    /// <li>
    /// <p>License configuration report - Reports the number and details of consumed licenses for a license configuration.</p></li>
    /// <li>
    /// <p>Resource report - Reports the tracked licenses and resource consumption for a license configuration.</p></li>
    /// </ul>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.r#type.is_none()`.
    pub fn r#type(&self) -> &[crate::types::ReportType] {
        self.r#type.as_deref().unwrap_or_default()
    }
    /// <p>The report context.</p>
    pub fn report_context(&self) -> ::std::option::Option<&crate::types::ReportContext> {
        self.report_context.as_ref()
    }
    /// <p>Frequency by which reports are generated.</p>
    pub fn report_frequency(&self) -> ::std::option::Option<&crate::types::ReportFrequency> {
        self.report_frequency.as_ref()
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn client_token(&self) -> ::std::option::Option<&str> {
        self.client_token.as_deref()
    }
    /// <p>Description of the report generator.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
}
impl UpdateLicenseManagerReportGeneratorInput {
    /// Creates a new builder-style object to manufacture [`UpdateLicenseManagerReportGeneratorInput`](crate::operation::update_license_manager_report_generator::UpdateLicenseManagerReportGeneratorInput).
    pub fn builder() -> crate::operation::update_license_manager_report_generator::builders::UpdateLicenseManagerReportGeneratorInputBuilder {
        crate::operation::update_license_manager_report_generator::builders::UpdateLicenseManagerReportGeneratorInputBuilder::default()
    }
}

/// A builder for [`UpdateLicenseManagerReportGeneratorInput`](crate::operation::update_license_manager_report_generator::UpdateLicenseManagerReportGeneratorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLicenseManagerReportGeneratorInputBuilder {
    pub(crate) license_manager_report_generator_arn: ::std::option::Option<::std::string::String>,
    pub(crate) report_generator_name: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<::std::vec::Vec<crate::types::ReportType>>,
    pub(crate) report_context: ::std::option::Option<crate::types::ReportContext>,
    pub(crate) report_frequency: ::std::option::Option<crate::types::ReportFrequency>,
    pub(crate) client_token: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
}
impl UpdateLicenseManagerReportGeneratorInputBuilder {
    /// <p>Amazon Resource Name (ARN) of the report generator to update.</p>
    /// This field is required.
    pub fn license_manager_report_generator_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.license_manager_report_generator_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Amazon Resource Name (ARN) of the report generator to update.</p>
    pub fn set_license_manager_report_generator_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.license_manager_report_generator_arn = input;
        self
    }
    /// <p>Amazon Resource Name (ARN) of the report generator to update.</p>
    pub fn get_license_manager_report_generator_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.license_manager_report_generator_arn
    }
    /// <p>Name of the report generator.</p>
    /// This field is required.
    pub fn report_generator_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.report_generator_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Name of the report generator.</p>
    pub fn set_report_generator_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.report_generator_name = input;
        self
    }
    /// <p>Name of the report generator.</p>
    pub fn get_report_generator_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.report_generator_name
    }
    /// Appends an item to `r#type`.
    ///
    /// To override the contents of this collection use [`set_type`](Self::set_type).
    ///
    /// <p>Type of reports to generate. The following report types are supported:</p>
    /// <ul>
    /// <li>
    /// <p>License configuration report - Reports the number and details of consumed licenses for a license configuration.</p></li>
    /// <li>
    /// <p>Resource report - Reports the tracked licenses and resource consumption for a license configuration.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::ReportType) -> Self {
        let mut v = self.r#type.unwrap_or_default();
        v.push(input);
        self.r#type = ::std::option::Option::Some(v);
        self
    }
    /// <p>Type of reports to generate. The following report types are supported:</p>
    /// <ul>
    /// <li>
    /// <p>License configuration report - Reports the number and details of consumed licenses for a license configuration.</p></li>
    /// <li>
    /// <p>Resource report - Reports the tracked licenses and resource consumption for a license configuration.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ReportType>>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>Type of reports to generate. The following report types are supported:</p>
    /// <ul>
    /// <li>
    /// <p>License configuration report - Reports the number and details of consumed licenses for a license configuration.</p></li>
    /// <li>
    /// <p>Resource report - Reports the tracked licenses and resource consumption for a license configuration.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ReportType>> {
        &self.r#type
    }
    /// <p>The report context.</p>
    /// This field is required.
    pub fn report_context(mut self, input: crate::types::ReportContext) -> Self {
        self.report_context = ::std::option::Option::Some(input);
        self
    }
    /// <p>The report context.</p>
    pub fn set_report_context(mut self, input: ::std::option::Option<crate::types::ReportContext>) -> Self {
        self.report_context = input;
        self
    }
    /// <p>The report context.</p>
    pub fn get_report_context(&self) -> &::std::option::Option<crate::types::ReportContext> {
        &self.report_context
    }
    /// <p>Frequency by which reports are generated.</p>
    /// This field is required.
    pub fn report_frequency(mut self, input: crate::types::ReportFrequency) -> Self {
        self.report_frequency = ::std::option::Option::Some(input);
        self
    }
    /// <p>Frequency by which reports are generated.</p>
    pub fn set_report_frequency(mut self, input: ::std::option::Option<crate::types::ReportFrequency>) -> Self {
        self.report_frequency = input;
        self
    }
    /// <p>Frequency by which reports are generated.</p>
    pub fn get_report_frequency(&self) -> &::std::option::Option<crate::types::ReportFrequency> {
        &self.report_frequency
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    /// This field is required.
    pub fn client_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.client_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn set_client_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.client_token = input;
        self
    }
    /// <p>Unique, case-sensitive identifier that you provide to ensure the idempotency of the request.</p>
    pub fn get_client_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.client_token
    }
    /// <p>Description of the report generator.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Description of the report generator.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>Description of the report generator.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Consumes the builder and constructs a [`UpdateLicenseManagerReportGeneratorInput`](crate::operation::update_license_manager_report_generator::UpdateLicenseManagerReportGeneratorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_license_manager_report_generator::UpdateLicenseManagerReportGeneratorInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::update_license_manager_report_generator::UpdateLicenseManagerReportGeneratorInput {
                license_manager_report_generator_arn: self.license_manager_report_generator_arn,
                report_generator_name: self.report_generator_name,
                r#type: self.r#type,
                report_context: self.report_context,
                report_frequency: self.report_frequency,
                client_token: self.client_token,
                description: self.description,
            },
        )
    }
}
