// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the job error.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Details {
    /// <p>Information about the job error.</p>
    pub import_asset_from_signed_url_job_error_details: ::std::option::Option<crate::types::ImportAssetFromSignedUrlJobErrorDetails>,
    /// <p>Details about the job error.</p>
    pub import_assets_from_s3_job_error_details: ::std::option::Option<::std::vec::Vec<crate::types::AssetSourceEntry>>,
}
impl Details {
    /// <p>Information about the job error.</p>
    pub fn import_asset_from_signed_url_job_error_details(&self) -> ::std::option::Option<&crate::types::ImportAssetFromSignedUrlJobErrorDetails> {
        self.import_asset_from_signed_url_job_error_details.as_ref()
    }
    /// <p>Details about the job error.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.import_assets_from_s3_job_error_details.is_none()`.
    pub fn import_assets_from_s3_job_error_details(&self) -> &[crate::types::AssetSourceEntry] {
        self.import_assets_from_s3_job_error_details.as_deref().unwrap_or_default()
    }
}
impl Details {
    /// Creates a new builder-style object to manufacture [`Details`](crate::types::Details).
    pub fn builder() -> crate::types::builders::DetailsBuilder {
        crate::types::builders::DetailsBuilder::default()
    }
}

/// A builder for [`Details`](crate::types::Details).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetailsBuilder {
    pub(crate) import_asset_from_signed_url_job_error_details: ::std::option::Option<crate::types::ImportAssetFromSignedUrlJobErrorDetails>,
    pub(crate) import_assets_from_s3_job_error_details: ::std::option::Option<::std::vec::Vec<crate::types::AssetSourceEntry>>,
}
impl DetailsBuilder {
    /// <p>Information about the job error.</p>
    pub fn import_asset_from_signed_url_job_error_details(mut self, input: crate::types::ImportAssetFromSignedUrlJobErrorDetails) -> Self {
        self.import_asset_from_signed_url_job_error_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the job error.</p>
    pub fn set_import_asset_from_signed_url_job_error_details(
        mut self,
        input: ::std::option::Option<crate::types::ImportAssetFromSignedUrlJobErrorDetails>,
    ) -> Self {
        self.import_asset_from_signed_url_job_error_details = input;
        self
    }
    /// <p>Information about the job error.</p>
    pub fn get_import_asset_from_signed_url_job_error_details(
        &self,
    ) -> &::std::option::Option<crate::types::ImportAssetFromSignedUrlJobErrorDetails> {
        &self.import_asset_from_signed_url_job_error_details
    }
    /// Appends an item to `import_assets_from_s3_job_error_details`.
    ///
    /// To override the contents of this collection use [`set_import_assets_from_s3_job_error_details`](Self::set_import_assets_from_s3_job_error_details).
    ///
    /// <p>Details about the job error.</p>
    pub fn import_assets_from_s3_job_error_details(mut self, input: crate::types::AssetSourceEntry) -> Self {
        let mut v = self.import_assets_from_s3_job_error_details.unwrap_or_default();
        v.push(input);
        self.import_assets_from_s3_job_error_details = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details about the job error.</p>
    pub fn set_import_assets_from_s3_job_error_details(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::AssetSourceEntry>>,
    ) -> Self {
        self.import_assets_from_s3_job_error_details = input;
        self
    }
    /// <p>Details about the job error.</p>
    pub fn get_import_assets_from_s3_job_error_details(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::AssetSourceEntry>> {
        &self.import_assets_from_s3_job_error_details
    }
    /// Consumes the builder and constructs a [`Details`](crate::types::Details).
    pub fn build(self) -> crate::types::Details {
        crate::types::Details {
            import_asset_from_signed_url_job_error_details: self.import_asset_from_signed_url_job_error_details,
            import_assets_from_s3_job_error_details: self.import_assets_from_s3_job_error_details,
        }
    }
}
