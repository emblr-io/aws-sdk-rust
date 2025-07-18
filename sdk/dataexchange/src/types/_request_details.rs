// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The details for the request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RequestDetails {
    /// <p>Details about the export to signed URL request.</p>
    pub export_asset_to_signed_url: ::std::option::Option<crate::types::ExportAssetToSignedUrlRequestDetails>,
    /// <p>Details about the export to Amazon S3 request.</p>
    pub export_assets_to_s3: ::std::option::Option<crate::types::ExportAssetsToS3RequestDetails>,
    /// <p>Details about the export to Amazon S3 request.</p>
    pub export_revisions_to_s3: ::std::option::Option<crate::types::ExportRevisionsToS3RequestDetails>,
    /// <p>Details about the import from Amazon S3 request.</p>
    pub import_asset_from_signed_url: ::std::option::Option<crate::types::ImportAssetFromSignedUrlRequestDetails>,
    /// <p>Details about the import asset from API Gateway API request.</p>
    pub import_assets_from_s3: ::std::option::Option<crate::types::ImportAssetsFromS3RequestDetails>,
    /// <p>Details from an import from Amazon Redshift datashare request.</p>
    pub import_assets_from_redshift_data_shares: ::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesRequestDetails>,
    /// <p>Details about the import from signed URL request.</p>
    pub import_asset_from_api_gateway_api: ::std::option::Option<crate::types::ImportAssetFromApiGatewayApiRequestDetails>,
    /// <p>Details of the request to create S3 data access from the Amazon S3 bucket.</p>
    pub create_s3_data_access_from_s3_bucket: ::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketRequestDetails>,
    /// <p>Request details for the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub import_assets_from_lake_formation_tag_policy: ::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyRequestDetails>,
}
impl RequestDetails {
    /// <p>Details about the export to signed URL request.</p>
    pub fn export_asset_to_signed_url(&self) -> ::std::option::Option<&crate::types::ExportAssetToSignedUrlRequestDetails> {
        self.export_asset_to_signed_url.as_ref()
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn export_assets_to_s3(&self) -> ::std::option::Option<&crate::types::ExportAssetsToS3RequestDetails> {
        self.export_assets_to_s3.as_ref()
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn export_revisions_to_s3(&self) -> ::std::option::Option<&crate::types::ExportRevisionsToS3RequestDetails> {
        self.export_revisions_to_s3.as_ref()
    }
    /// <p>Details about the import from Amazon S3 request.</p>
    pub fn import_asset_from_signed_url(&self) -> ::std::option::Option<&crate::types::ImportAssetFromSignedUrlRequestDetails> {
        self.import_asset_from_signed_url.as_ref()
    }
    /// <p>Details about the import asset from API Gateway API request.</p>
    pub fn import_assets_from_s3(&self) -> ::std::option::Option<&crate::types::ImportAssetsFromS3RequestDetails> {
        self.import_assets_from_s3.as_ref()
    }
    /// <p>Details from an import from Amazon Redshift datashare request.</p>
    pub fn import_assets_from_redshift_data_shares(&self) -> ::std::option::Option<&crate::types::ImportAssetsFromRedshiftDataSharesRequestDetails> {
        self.import_assets_from_redshift_data_shares.as_ref()
    }
    /// <p>Details about the import from signed URL request.</p>
    pub fn import_asset_from_api_gateway_api(&self) -> ::std::option::Option<&crate::types::ImportAssetFromApiGatewayApiRequestDetails> {
        self.import_asset_from_api_gateway_api.as_ref()
    }
    /// <p>Details of the request to create S3 data access from the Amazon S3 bucket.</p>
    pub fn create_s3_data_access_from_s3_bucket(&self) -> ::std::option::Option<&crate::types::CreateS3DataAccessFromS3BucketRequestDetails> {
        self.create_s3_data_access_from_s3_bucket.as_ref()
    }
    /// <p>Request details for the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn import_assets_from_lake_formation_tag_policy(
        &self,
    ) -> ::std::option::Option<&crate::types::ImportAssetsFromLakeFormationTagPolicyRequestDetails> {
        self.import_assets_from_lake_formation_tag_policy.as_ref()
    }
}
impl RequestDetails {
    /// Creates a new builder-style object to manufacture [`RequestDetails`](crate::types::RequestDetails).
    pub fn builder() -> crate::types::builders::RequestDetailsBuilder {
        crate::types::builders::RequestDetailsBuilder::default()
    }
}

/// A builder for [`RequestDetails`](crate::types::RequestDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RequestDetailsBuilder {
    pub(crate) export_asset_to_signed_url: ::std::option::Option<crate::types::ExportAssetToSignedUrlRequestDetails>,
    pub(crate) export_assets_to_s3: ::std::option::Option<crate::types::ExportAssetsToS3RequestDetails>,
    pub(crate) export_revisions_to_s3: ::std::option::Option<crate::types::ExportRevisionsToS3RequestDetails>,
    pub(crate) import_asset_from_signed_url: ::std::option::Option<crate::types::ImportAssetFromSignedUrlRequestDetails>,
    pub(crate) import_assets_from_s3: ::std::option::Option<crate::types::ImportAssetsFromS3RequestDetails>,
    pub(crate) import_assets_from_redshift_data_shares: ::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesRequestDetails>,
    pub(crate) import_asset_from_api_gateway_api: ::std::option::Option<crate::types::ImportAssetFromApiGatewayApiRequestDetails>,
    pub(crate) create_s3_data_access_from_s3_bucket: ::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketRequestDetails>,
    pub(crate) import_assets_from_lake_formation_tag_policy:
        ::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyRequestDetails>,
}
impl RequestDetailsBuilder {
    /// <p>Details about the export to signed URL request.</p>
    pub fn export_asset_to_signed_url(mut self, input: crate::types::ExportAssetToSignedUrlRequestDetails) -> Self {
        self.export_asset_to_signed_url = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the export to signed URL request.</p>
    pub fn set_export_asset_to_signed_url(mut self, input: ::std::option::Option<crate::types::ExportAssetToSignedUrlRequestDetails>) -> Self {
        self.export_asset_to_signed_url = input;
        self
    }
    /// <p>Details about the export to signed URL request.</p>
    pub fn get_export_asset_to_signed_url(&self) -> &::std::option::Option<crate::types::ExportAssetToSignedUrlRequestDetails> {
        &self.export_asset_to_signed_url
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn export_assets_to_s3(mut self, input: crate::types::ExportAssetsToS3RequestDetails) -> Self {
        self.export_assets_to_s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn set_export_assets_to_s3(mut self, input: ::std::option::Option<crate::types::ExportAssetsToS3RequestDetails>) -> Self {
        self.export_assets_to_s3 = input;
        self
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn get_export_assets_to_s3(&self) -> &::std::option::Option<crate::types::ExportAssetsToS3RequestDetails> {
        &self.export_assets_to_s3
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn export_revisions_to_s3(mut self, input: crate::types::ExportRevisionsToS3RequestDetails) -> Self {
        self.export_revisions_to_s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn set_export_revisions_to_s3(mut self, input: ::std::option::Option<crate::types::ExportRevisionsToS3RequestDetails>) -> Self {
        self.export_revisions_to_s3 = input;
        self
    }
    /// <p>Details about the export to Amazon S3 request.</p>
    pub fn get_export_revisions_to_s3(&self) -> &::std::option::Option<crate::types::ExportRevisionsToS3RequestDetails> {
        &self.export_revisions_to_s3
    }
    /// <p>Details about the import from Amazon S3 request.</p>
    pub fn import_asset_from_signed_url(mut self, input: crate::types::ImportAssetFromSignedUrlRequestDetails) -> Self {
        self.import_asset_from_signed_url = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the import from Amazon S3 request.</p>
    pub fn set_import_asset_from_signed_url(mut self, input: ::std::option::Option<crate::types::ImportAssetFromSignedUrlRequestDetails>) -> Self {
        self.import_asset_from_signed_url = input;
        self
    }
    /// <p>Details about the import from Amazon S3 request.</p>
    pub fn get_import_asset_from_signed_url(&self) -> &::std::option::Option<crate::types::ImportAssetFromSignedUrlRequestDetails> {
        &self.import_asset_from_signed_url
    }
    /// <p>Details about the import asset from API Gateway API request.</p>
    pub fn import_assets_from_s3(mut self, input: crate::types::ImportAssetsFromS3RequestDetails) -> Self {
        self.import_assets_from_s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the import asset from API Gateway API request.</p>
    pub fn set_import_assets_from_s3(mut self, input: ::std::option::Option<crate::types::ImportAssetsFromS3RequestDetails>) -> Self {
        self.import_assets_from_s3 = input;
        self
    }
    /// <p>Details about the import asset from API Gateway API request.</p>
    pub fn get_import_assets_from_s3(&self) -> &::std::option::Option<crate::types::ImportAssetsFromS3RequestDetails> {
        &self.import_assets_from_s3
    }
    /// <p>Details from an import from Amazon Redshift datashare request.</p>
    pub fn import_assets_from_redshift_data_shares(mut self, input: crate::types::ImportAssetsFromRedshiftDataSharesRequestDetails) -> Self {
        self.import_assets_from_redshift_data_shares = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details from an import from Amazon Redshift datashare request.</p>
    pub fn set_import_assets_from_redshift_data_shares(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesRequestDetails>,
    ) -> Self {
        self.import_assets_from_redshift_data_shares = input;
        self
    }
    /// <p>Details from an import from Amazon Redshift datashare request.</p>
    pub fn get_import_assets_from_redshift_data_shares(
        &self,
    ) -> &::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesRequestDetails> {
        &self.import_assets_from_redshift_data_shares
    }
    /// <p>Details about the import from signed URL request.</p>
    pub fn import_asset_from_api_gateway_api(mut self, input: crate::types::ImportAssetFromApiGatewayApiRequestDetails) -> Self {
        self.import_asset_from_api_gateway_api = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details about the import from signed URL request.</p>
    pub fn set_import_asset_from_api_gateway_api(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetFromApiGatewayApiRequestDetails>,
    ) -> Self {
        self.import_asset_from_api_gateway_api = input;
        self
    }
    /// <p>Details about the import from signed URL request.</p>
    pub fn get_import_asset_from_api_gateway_api(&self) -> &::std::option::Option<crate::types::ImportAssetFromApiGatewayApiRequestDetails> {
        &self.import_asset_from_api_gateway_api
    }
    /// <p>Details of the request to create S3 data access from the Amazon S3 bucket.</p>
    pub fn create_s3_data_access_from_s3_bucket(mut self, input: crate::types::CreateS3DataAccessFromS3BucketRequestDetails) -> Self {
        self.create_s3_data_access_from_s3_bucket = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details of the request to create S3 data access from the Amazon S3 bucket.</p>
    pub fn set_create_s3_data_access_from_s3_bucket(
        mut self,
        input: ::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketRequestDetails>,
    ) -> Self {
        self.create_s3_data_access_from_s3_bucket = input;
        self
    }
    /// <p>Details of the request to create S3 data access from the Amazon S3 bucket.</p>
    pub fn get_create_s3_data_access_from_s3_bucket(&self) -> &::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketRequestDetails> {
        &self.create_s3_data_access_from_s3_bucket
    }
    /// <p>Request details for the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn import_assets_from_lake_formation_tag_policy(mut self, input: crate::types::ImportAssetsFromLakeFormationTagPolicyRequestDetails) -> Self {
        self.import_assets_from_lake_formation_tag_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Request details for the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn set_import_assets_from_lake_formation_tag_policy(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyRequestDetails>,
    ) -> Self {
        self.import_assets_from_lake_formation_tag_policy = input;
        self
    }
    /// <p>Request details for the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn get_import_assets_from_lake_formation_tag_policy(
        &self,
    ) -> &::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyRequestDetails> {
        &self.import_assets_from_lake_formation_tag_policy
    }
    /// Consumes the builder and constructs a [`RequestDetails`](crate::types::RequestDetails).
    pub fn build(self) -> crate::types::RequestDetails {
        crate::types::RequestDetails {
            export_asset_to_signed_url: self.export_asset_to_signed_url,
            export_assets_to_s3: self.export_assets_to_s3,
            export_revisions_to_s3: self.export_revisions_to_s3,
            import_asset_from_signed_url: self.import_asset_from_signed_url,
            import_assets_from_s3: self.import_assets_from_s3,
            import_assets_from_redshift_data_shares: self.import_assets_from_redshift_data_shares,
            import_asset_from_api_gateway_api: self.import_asset_from_api_gateway_api,
            create_s3_data_access_from_s3_bucket: self.create_s3_data_access_from_s3_bucket,
            import_assets_from_lake_formation_tag_policy: self.import_assets_from_lake_formation_tag_policy,
        }
    }
}
