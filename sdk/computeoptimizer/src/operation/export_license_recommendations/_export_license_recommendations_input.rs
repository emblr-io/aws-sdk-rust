// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExportLicenseRecommendationsInput {
    /// <p>The IDs of the Amazon Web Services accounts for which to export license recommendations.</p>
    /// <p>If your account is the management account of an organization, use this parameter to specify the member account for which you want to export recommendations.</p>
    /// <p>This parameter can't be specified together with the include member accounts parameter. The parameters are mutually exclusive.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts aren't included in the export.</p>
    /// <p>You can specify multiple account IDs per request.</p>
    pub account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>An array of objects to specify a filter that exports a more specific set of license recommendations.</p>
    pub filters: ::std::option::Option<::std::vec::Vec<crate::types::LicenseRecommendationFilter>>,
    /// <p>The recommendations data to include in the export file. For more information about the fields that can be exported, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/exporting-recommendations.html#exported-files">Exported files</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fields_to_export: ::std::option::Option<::std::vec::Vec<crate::types::ExportableLicenseField>>,
    /// <p>Describes the destination Amazon Simple Storage Service (Amazon S3) bucket name and key prefix for a recommendations export job.</p>
    /// <p>You must create the destination Amazon S3 bucket for your recommendations export before you create the export job. Compute Optimizer does not create the S3 bucket for you. After you create the S3 bucket, ensure that it has the required permission policy to allow Compute Optimizer to write the export file to it. If you plan to specify an object prefix when you create the export job, you must include the object prefix in the policy that you add to the S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/create-s3-bucket-policy-for-compute-optimizer.html">Amazon S3 Bucket Policy for Compute Optimizer</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub s3_destination_config: ::std::option::Option<crate::types::S3DestinationConfig>,
    /// <p>The format of the export file.</p>
    /// <p>A CSV file is the only export format currently supported.</p>
    pub file_format: ::std::option::Option<crate::types::FileFormat>,
    /// <p>Indicates whether to include recommendations for resources in all member accounts of the organization if your account is the management account of an organization.</p>
    /// <p>The member accounts must also be opted in to Compute Optimizer, and trusted access for Compute Optimizer must be enabled in the organization account. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/security-iam.html#trusted-service-access">Compute Optimizer and Amazon Web Services Organizations trusted access</a> in the <i>Compute Optimizer User Guide</i>.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts of the organization aren't included in the export file .</p>
    /// <p>This parameter cannot be specified together with the account IDs parameter. The parameters are mutually exclusive.</p>
    pub include_member_accounts: ::std::option::Option<bool>,
}
impl ExportLicenseRecommendationsInput {
    /// <p>The IDs of the Amazon Web Services accounts for which to export license recommendations.</p>
    /// <p>If your account is the management account of an organization, use this parameter to specify the member account for which you want to export recommendations.</p>
    /// <p>This parameter can't be specified together with the include member accounts parameter. The parameters are mutually exclusive.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts aren't included in the export.</p>
    /// <p>You can specify multiple account IDs per request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.account_ids.is_none()`.
    pub fn account_ids(&self) -> &[::std::string::String] {
        self.account_ids.as_deref().unwrap_or_default()
    }
    /// <p>An array of objects to specify a filter that exports a more specific set of license recommendations.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.filters.is_none()`.
    pub fn filters(&self) -> &[crate::types::LicenseRecommendationFilter] {
        self.filters.as_deref().unwrap_or_default()
    }
    /// <p>The recommendations data to include in the export file. For more information about the fields that can be exported, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/exporting-recommendations.html#exported-files">Exported files</a> in the <i>Compute Optimizer User Guide</i>.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.fields_to_export.is_none()`.
    pub fn fields_to_export(&self) -> &[crate::types::ExportableLicenseField] {
        self.fields_to_export.as_deref().unwrap_or_default()
    }
    /// <p>Describes the destination Amazon Simple Storage Service (Amazon S3) bucket name and key prefix for a recommendations export job.</p>
    /// <p>You must create the destination Amazon S3 bucket for your recommendations export before you create the export job. Compute Optimizer does not create the S3 bucket for you. After you create the S3 bucket, ensure that it has the required permission policy to allow Compute Optimizer to write the export file to it. If you plan to specify an object prefix when you create the export job, you must include the object prefix in the policy that you add to the S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/create-s3-bucket-policy-for-compute-optimizer.html">Amazon S3 Bucket Policy for Compute Optimizer</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn s3_destination_config(&self) -> ::std::option::Option<&crate::types::S3DestinationConfig> {
        self.s3_destination_config.as_ref()
    }
    /// <p>The format of the export file.</p>
    /// <p>A CSV file is the only export format currently supported.</p>
    pub fn file_format(&self) -> ::std::option::Option<&crate::types::FileFormat> {
        self.file_format.as_ref()
    }
    /// <p>Indicates whether to include recommendations for resources in all member accounts of the organization if your account is the management account of an organization.</p>
    /// <p>The member accounts must also be opted in to Compute Optimizer, and trusted access for Compute Optimizer must be enabled in the organization account. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/security-iam.html#trusted-service-access">Compute Optimizer and Amazon Web Services Organizations trusted access</a> in the <i>Compute Optimizer User Guide</i>.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts of the organization aren't included in the export file .</p>
    /// <p>This parameter cannot be specified together with the account IDs parameter. The parameters are mutually exclusive.</p>
    pub fn include_member_accounts(&self) -> ::std::option::Option<bool> {
        self.include_member_accounts
    }
}
impl ExportLicenseRecommendationsInput {
    /// Creates a new builder-style object to manufacture [`ExportLicenseRecommendationsInput`](crate::operation::export_license_recommendations::ExportLicenseRecommendationsInput).
    pub fn builder() -> crate::operation::export_license_recommendations::builders::ExportLicenseRecommendationsInputBuilder {
        crate::operation::export_license_recommendations::builders::ExportLicenseRecommendationsInputBuilder::default()
    }
}

/// A builder for [`ExportLicenseRecommendationsInput`](crate::operation::export_license_recommendations::ExportLicenseRecommendationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExportLicenseRecommendationsInputBuilder {
    pub(crate) account_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) filters: ::std::option::Option<::std::vec::Vec<crate::types::LicenseRecommendationFilter>>,
    pub(crate) fields_to_export: ::std::option::Option<::std::vec::Vec<crate::types::ExportableLicenseField>>,
    pub(crate) s3_destination_config: ::std::option::Option<crate::types::S3DestinationConfig>,
    pub(crate) file_format: ::std::option::Option<crate::types::FileFormat>,
    pub(crate) include_member_accounts: ::std::option::Option<bool>,
}
impl ExportLicenseRecommendationsInputBuilder {
    /// Appends an item to `account_ids`.
    ///
    /// To override the contents of this collection use [`set_account_ids`](Self::set_account_ids).
    ///
    /// <p>The IDs of the Amazon Web Services accounts for which to export license recommendations.</p>
    /// <p>If your account is the management account of an organization, use this parameter to specify the member account for which you want to export recommendations.</p>
    /// <p>This parameter can't be specified together with the include member accounts parameter. The parameters are mutually exclusive.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts aren't included in the export.</p>
    /// <p>You can specify multiple account IDs per request.</p>
    pub fn account_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.account_ids.unwrap_or_default();
        v.push(input.into());
        self.account_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the Amazon Web Services accounts for which to export license recommendations.</p>
    /// <p>If your account is the management account of an organization, use this parameter to specify the member account for which you want to export recommendations.</p>
    /// <p>This parameter can't be specified together with the include member accounts parameter. The parameters are mutually exclusive.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts aren't included in the export.</p>
    /// <p>You can specify multiple account IDs per request.</p>
    pub fn set_account_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.account_ids = input;
        self
    }
    /// <p>The IDs of the Amazon Web Services accounts for which to export license recommendations.</p>
    /// <p>If your account is the management account of an organization, use this parameter to specify the member account for which you want to export recommendations.</p>
    /// <p>This parameter can't be specified together with the include member accounts parameter. The parameters are mutually exclusive.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts aren't included in the export.</p>
    /// <p>You can specify multiple account IDs per request.</p>
    pub fn get_account_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.account_ids
    }
    /// Appends an item to `filters`.
    ///
    /// To override the contents of this collection use [`set_filters`](Self::set_filters).
    ///
    /// <p>An array of objects to specify a filter that exports a more specific set of license recommendations.</p>
    pub fn filters(mut self, input: crate::types::LicenseRecommendationFilter) -> Self {
        let mut v = self.filters.unwrap_or_default();
        v.push(input);
        self.filters = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of objects to specify a filter that exports a more specific set of license recommendations.</p>
    pub fn set_filters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::LicenseRecommendationFilter>>) -> Self {
        self.filters = input;
        self
    }
    /// <p>An array of objects to specify a filter that exports a more specific set of license recommendations.</p>
    pub fn get_filters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::LicenseRecommendationFilter>> {
        &self.filters
    }
    /// Appends an item to `fields_to_export`.
    ///
    /// To override the contents of this collection use [`set_fields_to_export`](Self::set_fields_to_export).
    ///
    /// <p>The recommendations data to include in the export file. For more information about the fields that can be exported, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/exporting-recommendations.html#exported-files">Exported files</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn fields_to_export(mut self, input: crate::types::ExportableLicenseField) -> Self {
        let mut v = self.fields_to_export.unwrap_or_default();
        v.push(input);
        self.fields_to_export = ::std::option::Option::Some(v);
        self
    }
    /// <p>The recommendations data to include in the export file. For more information about the fields that can be exported, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/exporting-recommendations.html#exported-files">Exported files</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn set_fields_to_export(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ExportableLicenseField>>) -> Self {
        self.fields_to_export = input;
        self
    }
    /// <p>The recommendations data to include in the export file. For more information about the fields that can be exported, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/exporting-recommendations.html#exported-files">Exported files</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn get_fields_to_export(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ExportableLicenseField>> {
        &self.fields_to_export
    }
    /// <p>Describes the destination Amazon Simple Storage Service (Amazon S3) bucket name and key prefix for a recommendations export job.</p>
    /// <p>You must create the destination Amazon S3 bucket for your recommendations export before you create the export job. Compute Optimizer does not create the S3 bucket for you. After you create the S3 bucket, ensure that it has the required permission policy to allow Compute Optimizer to write the export file to it. If you plan to specify an object prefix when you create the export job, you must include the object prefix in the policy that you add to the S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/create-s3-bucket-policy-for-compute-optimizer.html">Amazon S3 Bucket Policy for Compute Optimizer</a> in the <i>Compute Optimizer User Guide</i>.</p>
    /// This field is required.
    pub fn s3_destination_config(mut self, input: crate::types::S3DestinationConfig) -> Self {
        self.s3_destination_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Describes the destination Amazon Simple Storage Service (Amazon S3) bucket name and key prefix for a recommendations export job.</p>
    /// <p>You must create the destination Amazon S3 bucket for your recommendations export before you create the export job. Compute Optimizer does not create the S3 bucket for you. After you create the S3 bucket, ensure that it has the required permission policy to allow Compute Optimizer to write the export file to it. If you plan to specify an object prefix when you create the export job, you must include the object prefix in the policy that you add to the S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/create-s3-bucket-policy-for-compute-optimizer.html">Amazon S3 Bucket Policy for Compute Optimizer</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn set_s3_destination_config(mut self, input: ::std::option::Option<crate::types::S3DestinationConfig>) -> Self {
        self.s3_destination_config = input;
        self
    }
    /// <p>Describes the destination Amazon Simple Storage Service (Amazon S3) bucket name and key prefix for a recommendations export job.</p>
    /// <p>You must create the destination Amazon S3 bucket for your recommendations export before you create the export job. Compute Optimizer does not create the S3 bucket for you. After you create the S3 bucket, ensure that it has the required permission policy to allow Compute Optimizer to write the export file to it. If you plan to specify an object prefix when you create the export job, you must include the object prefix in the policy that you add to the S3 bucket. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/create-s3-bucket-policy-for-compute-optimizer.html">Amazon S3 Bucket Policy for Compute Optimizer</a> in the <i>Compute Optimizer User Guide</i>.</p>
    pub fn get_s3_destination_config(&self) -> &::std::option::Option<crate::types::S3DestinationConfig> {
        &self.s3_destination_config
    }
    /// <p>The format of the export file.</p>
    /// <p>A CSV file is the only export format currently supported.</p>
    pub fn file_format(mut self, input: crate::types::FileFormat) -> Self {
        self.file_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format of the export file.</p>
    /// <p>A CSV file is the only export format currently supported.</p>
    pub fn set_file_format(mut self, input: ::std::option::Option<crate::types::FileFormat>) -> Self {
        self.file_format = input;
        self
    }
    /// <p>The format of the export file.</p>
    /// <p>A CSV file is the only export format currently supported.</p>
    pub fn get_file_format(&self) -> &::std::option::Option<crate::types::FileFormat> {
        &self.file_format
    }
    /// <p>Indicates whether to include recommendations for resources in all member accounts of the organization if your account is the management account of an organization.</p>
    /// <p>The member accounts must also be opted in to Compute Optimizer, and trusted access for Compute Optimizer must be enabled in the organization account. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/security-iam.html#trusted-service-access">Compute Optimizer and Amazon Web Services Organizations trusted access</a> in the <i>Compute Optimizer User Guide</i>.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts of the organization aren't included in the export file .</p>
    /// <p>This parameter cannot be specified together with the account IDs parameter. The parameters are mutually exclusive.</p>
    pub fn include_member_accounts(mut self, input: bool) -> Self {
        self.include_member_accounts = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to include recommendations for resources in all member accounts of the organization if your account is the management account of an organization.</p>
    /// <p>The member accounts must also be opted in to Compute Optimizer, and trusted access for Compute Optimizer must be enabled in the organization account. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/security-iam.html#trusted-service-access">Compute Optimizer and Amazon Web Services Organizations trusted access</a> in the <i>Compute Optimizer User Guide</i>.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts of the organization aren't included in the export file .</p>
    /// <p>This parameter cannot be specified together with the account IDs parameter. The parameters are mutually exclusive.</p>
    pub fn set_include_member_accounts(mut self, input: ::std::option::Option<bool>) -> Self {
        self.include_member_accounts = input;
        self
    }
    /// <p>Indicates whether to include recommendations for resources in all member accounts of the organization if your account is the management account of an organization.</p>
    /// <p>The member accounts must also be opted in to Compute Optimizer, and trusted access for Compute Optimizer must be enabled in the organization account. For more information, see <a href="https://docs.aws.amazon.com/compute-optimizer/latest/ug/security-iam.html#trusted-service-access">Compute Optimizer and Amazon Web Services Organizations trusted access</a> in the <i>Compute Optimizer User Guide</i>.</p>
    /// <p>If this parameter is omitted, recommendations for member accounts of the organization aren't included in the export file .</p>
    /// <p>This parameter cannot be specified together with the account IDs parameter. The parameters are mutually exclusive.</p>
    pub fn get_include_member_accounts(&self) -> &::std::option::Option<bool> {
        &self.include_member_accounts
    }
    /// Consumes the builder and constructs a [`ExportLicenseRecommendationsInput`](crate::operation::export_license_recommendations::ExportLicenseRecommendationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::export_license_recommendations::ExportLicenseRecommendationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::export_license_recommendations::ExportLicenseRecommendationsInput {
            account_ids: self.account_ids,
            filters: self.filters,
            fields_to_export: self.fields_to_export,
            s3_destination_config: self.s3_destination_config,
            file_format: self.file_format,
            include_member_accounts: self.include_member_accounts,
        })
    }
}
