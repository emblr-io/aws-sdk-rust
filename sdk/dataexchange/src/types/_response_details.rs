// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details for the response.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ResponseDetails {
    /// <p>Details for the export to signed URL response.</p>
    pub export_asset_to_signed_url: ::std::option::Option<crate::types::ExportAssetToSignedUrlResponseDetails>,
    /// <p>Details for the export to Amazon S3 response.</p>
    pub export_assets_to_s3: ::std::option::Option<crate::types::ExportAssetsToS3ResponseDetails>,
    /// <p>Details for the export revisions to Amazon S3 response.</p>
    pub export_revisions_to_s3: ::std::option::Option<crate::types::ExportRevisionsToS3ResponseDetails>,
    /// <p>Details for the import from signed URL response.</p>
    pub import_asset_from_signed_url: ::std::option::Option<crate::types::ImportAssetFromSignedUrlResponseDetails>,
    /// <p>Details for the import from Amazon S3 response.</p>
    pub import_assets_from_s3: ::std::option::Option<crate::types::ImportAssetsFromS3ResponseDetails>,
    /// <p>Details from an import from Amazon Redshift datashare response.</p>
    pub import_assets_from_redshift_data_shares: ::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesResponseDetails>,
    /// <p>The response details.</p>
    pub import_asset_from_api_gateway_api: ::std::option::Option<crate::types::ImportAssetFromApiGatewayApiResponseDetails>,
    /// <p>Response details from the CreateS3DataAccessFromS3Bucket job.</p>
    pub create_s3_data_access_from_s3_bucket: ::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketResponseDetails>,
    /// <p>Response details from the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub import_assets_from_lake_formation_tag_policy: ::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyResponseDetails>,
}
impl ResponseDetails {
    /// <p>Details for the export to signed URL response.</p>
    pub fn export_asset_to_signed_url(&self) -> ::std::option::Option<&crate::types::ExportAssetToSignedUrlResponseDetails> {
        self.export_asset_to_signed_url.as_ref()
    }
    /// <p>Details for the export to Amazon S3 response.</p>
    pub fn export_assets_to_s3(&self) -> ::std::option::Option<&crate::types::ExportAssetsToS3ResponseDetails> {
        self.export_assets_to_s3.as_ref()
    }
    /// <p>Details for the export revisions to Amazon S3 response.</p>
    pub fn export_revisions_to_s3(&self) -> ::std::option::Option<&crate::types::ExportRevisionsToS3ResponseDetails> {
        self.export_revisions_to_s3.as_ref()
    }
    /// <p>Details for the import from signed URL response.</p>
    pub fn import_asset_from_signed_url(&self) -> ::std::option::Option<&crate::types::ImportAssetFromSignedUrlResponseDetails> {
        self.import_asset_from_signed_url.as_ref()
    }
    /// <p>Details for the import from Amazon S3 response.</p>
    pub fn import_assets_from_s3(&self) -> ::std::option::Option<&crate::types::ImportAssetsFromS3ResponseDetails> {
        self.import_assets_from_s3.as_ref()
    }
    /// <p>Details from an import from Amazon Redshift datashare response.</p>
    pub fn import_assets_from_redshift_data_shares(&self) -> ::std::option::Option<&crate::types::ImportAssetsFromRedshiftDataSharesResponseDetails> {
        self.import_assets_from_redshift_data_shares.as_ref()
    }
    /// <p>The response details.</p>
    pub fn import_asset_from_api_gateway_api(&self) -> ::std::option::Option<&crate::types::ImportAssetFromApiGatewayApiResponseDetails> {
        self.import_asset_from_api_gateway_api.as_ref()
    }
    /// <p>Response details from the CreateS3DataAccessFromS3Bucket job.</p>
    pub fn create_s3_data_access_from_s3_bucket(&self) -> ::std::option::Option<&crate::types::CreateS3DataAccessFromS3BucketResponseDetails> {
        self.create_s3_data_access_from_s3_bucket.as_ref()
    }
    /// <p>Response details from the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn import_assets_from_lake_formation_tag_policy(
        &self,
    ) -> ::std::option::Option<&crate::types::ImportAssetsFromLakeFormationTagPolicyResponseDetails> {
        self.import_assets_from_lake_formation_tag_policy.as_ref()
    }
}
impl ResponseDetails {
    /// Creates a new builder-style object to manufacture [`ResponseDetails`](crate::types::ResponseDetails).
    pub fn builder() -> crate::types::builders::ResponseDetailsBuilder {
        crate::types::builders::ResponseDetailsBuilder::default()
    }
}

/// A builder for [`ResponseDetails`](crate::types::ResponseDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ResponseDetailsBuilder {
    pub(crate) export_asset_to_signed_url: ::std::option::Option<crate::types::ExportAssetToSignedUrlResponseDetails>,
    pub(crate) export_assets_to_s3: ::std::option::Option<crate::types::ExportAssetsToS3ResponseDetails>,
    pub(crate) export_revisions_to_s3: ::std::option::Option<crate::types::ExportRevisionsToS3ResponseDetails>,
    pub(crate) import_asset_from_signed_url: ::std::option::Option<crate::types::ImportAssetFromSignedUrlResponseDetails>,
    pub(crate) import_assets_from_s3: ::std::option::Option<crate::types::ImportAssetsFromS3ResponseDetails>,
    pub(crate) import_assets_from_redshift_data_shares: ::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesResponseDetails>,
    pub(crate) import_asset_from_api_gateway_api: ::std::option::Option<crate::types::ImportAssetFromApiGatewayApiResponseDetails>,
    pub(crate) create_s3_data_access_from_s3_bucket: ::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketResponseDetails>,
    pub(crate) import_assets_from_lake_formation_tag_policy:
        ::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyResponseDetails>,
}
impl ResponseDetailsBuilder {
    /// <p>Details for the export to signed URL response.</p>
    pub fn export_asset_to_signed_url(mut self, input: crate::types::ExportAssetToSignedUrlResponseDetails) -> Self {
        self.export_asset_to_signed_url = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the export to signed URL response.</p>
    pub fn set_export_asset_to_signed_url(mut self, input: ::std::option::Option<crate::types::ExportAssetToSignedUrlResponseDetails>) -> Self {
        self.export_asset_to_signed_url = input;
        self
    }
    /// <p>Details for the export to signed URL response.</p>
    pub fn get_export_asset_to_signed_url(&self) -> &::std::option::Option<crate::types::ExportAssetToSignedUrlResponseDetails> {
        &self.export_asset_to_signed_url
    }
    /// <p>Details for the export to Amazon S3 response.</p>
    pub fn export_assets_to_s3(mut self, input: crate::types::ExportAssetsToS3ResponseDetails) -> Self {
        self.export_assets_to_s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the export to Amazon S3 response.</p>
    pub fn set_export_assets_to_s3(mut self, input: ::std::option::Option<crate::types::ExportAssetsToS3ResponseDetails>) -> Self {
        self.export_assets_to_s3 = input;
        self
    }
    /// <p>Details for the export to Amazon S3 response.</p>
    pub fn get_export_assets_to_s3(&self) -> &::std::option::Option<crate::types::ExportAssetsToS3ResponseDetails> {
        &self.export_assets_to_s3
    }
    /// <p>Details for the export revisions to Amazon S3 response.</p>
    pub fn export_revisions_to_s3(mut self, input: crate::types::ExportRevisionsToS3ResponseDetails) -> Self {
        self.export_revisions_to_s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the export revisions to Amazon S3 response.</p>
    pub fn set_export_revisions_to_s3(mut self, input: ::std::option::Option<crate::types::ExportRevisionsToS3ResponseDetails>) -> Self {
        self.export_revisions_to_s3 = input;
        self
    }
    /// <p>Details for the export revisions to Amazon S3 response.</p>
    pub fn get_export_revisions_to_s3(&self) -> &::std::option::Option<crate::types::ExportRevisionsToS3ResponseDetails> {
        &self.export_revisions_to_s3
    }
    /// <p>Details for the import from signed URL response.</p>
    pub fn import_asset_from_signed_url(mut self, input: crate::types::ImportAssetFromSignedUrlResponseDetails) -> Self {
        self.import_asset_from_signed_url = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the import from signed URL response.</p>
    pub fn set_import_asset_from_signed_url(mut self, input: ::std::option::Option<crate::types::ImportAssetFromSignedUrlResponseDetails>) -> Self {
        self.import_asset_from_signed_url = input;
        self
    }
    /// <p>Details for the import from signed URL response.</p>
    pub fn get_import_asset_from_signed_url(&self) -> &::std::option::Option<crate::types::ImportAssetFromSignedUrlResponseDetails> {
        &self.import_asset_from_signed_url
    }
    /// <p>Details for the import from Amazon S3 response.</p>
    pub fn import_assets_from_s3(mut self, input: crate::types::ImportAssetsFromS3ResponseDetails) -> Self {
        self.import_assets_from_s3 = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details for the import from Amazon S3 response.</p>
    pub fn set_import_assets_from_s3(mut self, input: ::std::option::Option<crate::types::ImportAssetsFromS3ResponseDetails>) -> Self {
        self.import_assets_from_s3 = input;
        self
    }
    /// <p>Details for the import from Amazon S3 response.</p>
    pub fn get_import_assets_from_s3(&self) -> &::std::option::Option<crate::types::ImportAssetsFromS3ResponseDetails> {
        &self.import_assets_from_s3
    }
    /// <p>Details from an import from Amazon Redshift datashare response.</p>
    pub fn import_assets_from_redshift_data_shares(mut self, input: crate::types::ImportAssetsFromRedshiftDataSharesResponseDetails) -> Self {
        self.import_assets_from_redshift_data_shares = ::std::option::Option::Some(input);
        self
    }
    /// <p>Details from an import from Amazon Redshift datashare response.</p>
    pub fn set_import_assets_from_redshift_data_shares(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesResponseDetails>,
    ) -> Self {
        self.import_assets_from_redshift_data_shares = input;
        self
    }
    /// <p>Details from an import from Amazon Redshift datashare response.</p>
    pub fn get_import_assets_from_redshift_data_shares(
        &self,
    ) -> &::std::option::Option<crate::types::ImportAssetsFromRedshiftDataSharesResponseDetails> {
        &self.import_assets_from_redshift_data_shares
    }
    /// <p>The response details.</p>
    pub fn import_asset_from_api_gateway_api(mut self, input: crate::types::ImportAssetFromApiGatewayApiResponseDetails) -> Self {
        self.import_asset_from_api_gateway_api = ::std::option::Option::Some(input);
        self
    }
    /// <p>The response details.</p>
    pub fn set_import_asset_from_api_gateway_api(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetFromApiGatewayApiResponseDetails>,
    ) -> Self {
        self.import_asset_from_api_gateway_api = input;
        self
    }
    /// <p>The response details.</p>
    pub fn get_import_asset_from_api_gateway_api(&self) -> &::std::option::Option<crate::types::ImportAssetFromApiGatewayApiResponseDetails> {
        &self.import_asset_from_api_gateway_api
    }
    /// <p>Response details from the CreateS3DataAccessFromS3Bucket job.</p>
    pub fn create_s3_data_access_from_s3_bucket(mut self, input: crate::types::CreateS3DataAccessFromS3BucketResponseDetails) -> Self {
        self.create_s3_data_access_from_s3_bucket = ::std::option::Option::Some(input);
        self
    }
    /// <p>Response details from the CreateS3DataAccessFromS3Bucket job.</p>
    pub fn set_create_s3_data_access_from_s3_bucket(
        mut self,
        input: ::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketResponseDetails>,
    ) -> Self {
        self.create_s3_data_access_from_s3_bucket = input;
        self
    }
    /// <p>Response details from the CreateS3DataAccessFromS3Bucket job.</p>
    pub fn get_create_s3_data_access_from_s3_bucket(&self) -> &::std::option::Option<crate::types::CreateS3DataAccessFromS3BucketResponseDetails> {
        &self.create_s3_data_access_from_s3_bucket
    }
    /// <p>Response details from the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn import_assets_from_lake_formation_tag_policy(
        mut self,
        input: crate::types::ImportAssetsFromLakeFormationTagPolicyResponseDetails,
    ) -> Self {
        self.import_assets_from_lake_formation_tag_policy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Response details from the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn set_import_assets_from_lake_formation_tag_policy(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyResponseDetails>,
    ) -> Self {
        self.import_assets_from_lake_formation_tag_policy = input;
        self
    }
    /// <p>Response details from the ImportAssetsFromLakeFormationTagPolicy job.</p>
    pub fn get_import_assets_from_lake_formation_tag_policy(
        &self,
    ) -> &::std::option::Option<crate::types::ImportAssetsFromLakeFormationTagPolicyResponseDetails> {
        &self.import_assets_from_lake_formation_tag_policy
    }
    /// Consumes the builder and constructs a [`ResponseDetails`](crate::types::ResponseDetails).
    pub fn build(self) -> crate::types::ResponseDetails {
        crate::types::ResponseDetails {
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
