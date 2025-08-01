// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A container for the information associated with a <a href="https://docs.aws.amazon.com/AmazonS3/latest/API/API_control_CreateMultiRegionAccessPoint.html">CreateMultiRegionAccessPoint</a> request.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMultiRegionAccessPointInput {
    /// <p>The name of the Multi-Region Access Point associated with this request.</p>
    pub name: ::std::string::String,
    /// <p>The <code>PublicAccessBlock</code> configuration that you want to apply to this Amazon S3 account. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status">The Meaning of "Public"</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>This data type is not supported for Amazon S3 on Outposts.</p>
    pub public_access_block: ::std::option::Option<crate::types::PublicAccessBlockConfiguration>,
    /// <p>The buckets in different Regions that are associated with the Multi-Region Access Point.</p>
    pub regions: ::std::vec::Vec<crate::types::Region>,
}
impl CreateMultiRegionAccessPointInput {
    /// <p>The name of the Multi-Region Access Point associated with this request.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
    /// <p>The <code>PublicAccessBlock</code> configuration that you want to apply to this Amazon S3 account. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status">The Meaning of "Public"</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>This data type is not supported for Amazon S3 on Outposts.</p>
    pub fn public_access_block(&self) -> ::std::option::Option<&crate::types::PublicAccessBlockConfiguration> {
        self.public_access_block.as_ref()
    }
    /// <p>The buckets in different Regions that are associated with the Multi-Region Access Point.</p>
    pub fn regions(&self) -> &[crate::types::Region] {
        use std::ops::Deref;
        self.regions.deref()
    }
}
impl CreateMultiRegionAccessPointInput {
    /// Creates a new builder-style object to manufacture [`CreateMultiRegionAccessPointInput`](crate::types::CreateMultiRegionAccessPointInput).
    pub fn builder() -> crate::types::builders::CreateMultiRegionAccessPointInputBuilder {
        crate::types::builders::CreateMultiRegionAccessPointInputBuilder::default()
    }
}

/// A builder for [`CreateMultiRegionAccessPointInput`](crate::types::CreateMultiRegionAccessPointInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMultiRegionAccessPointInputBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) public_access_block: ::std::option::Option<crate::types::PublicAccessBlockConfiguration>,
    pub(crate) regions: ::std::option::Option<::std::vec::Vec<crate::types::Region>>,
}
impl CreateMultiRegionAccessPointInputBuilder {
    /// <p>The name of the Multi-Region Access Point associated with this request.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Multi-Region Access Point associated with this request.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the Multi-Region Access Point associated with this request.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The <code>PublicAccessBlock</code> configuration that you want to apply to this Amazon S3 account. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status">The Meaning of "Public"</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>This data type is not supported for Amazon S3 on Outposts.</p>
    pub fn public_access_block(mut self, input: crate::types::PublicAccessBlockConfiguration) -> Self {
        self.public_access_block = ::std::option::Option::Some(input);
        self
    }
    /// <p>The <code>PublicAccessBlock</code> configuration that you want to apply to this Amazon S3 account. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status">The Meaning of "Public"</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>This data type is not supported for Amazon S3 on Outposts.</p>
    pub fn set_public_access_block(mut self, input: ::std::option::Option<crate::types::PublicAccessBlockConfiguration>) -> Self {
        self.public_access_block = input;
        self
    }
    /// <p>The <code>PublicAccessBlock</code> configuration that you want to apply to this Amazon S3 account. You can enable the configuration options in any combination. For more information about when Amazon S3 considers a bucket or object public, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html#access-control-block-public-access-policy-status">The Meaning of "Public"</a> in the <i>Amazon S3 User Guide</i>.</p>
    /// <p>This data type is not supported for Amazon S3 on Outposts.</p>
    pub fn get_public_access_block(&self) -> &::std::option::Option<crate::types::PublicAccessBlockConfiguration> {
        &self.public_access_block
    }
    /// Appends an item to `regions`.
    ///
    /// To override the contents of this collection use [`set_regions`](Self::set_regions).
    ///
    /// <p>The buckets in different Regions that are associated with the Multi-Region Access Point.</p>
    pub fn regions(mut self, input: crate::types::Region) -> Self {
        let mut v = self.regions.unwrap_or_default();
        v.push(input);
        self.regions = ::std::option::Option::Some(v);
        self
    }
    /// <p>The buckets in different Regions that are associated with the Multi-Region Access Point.</p>
    pub fn set_regions(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Region>>) -> Self {
        self.regions = input;
        self
    }
    /// <p>The buckets in different Regions that are associated with the Multi-Region Access Point.</p>
    pub fn get_regions(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Region>> {
        &self.regions
    }
    /// Consumes the builder and constructs a [`CreateMultiRegionAccessPointInput`](crate::types::CreateMultiRegionAccessPointInput).
    /// This method will fail if any of the following fields are not set:
    /// - [`name`](crate::types::builders::CreateMultiRegionAccessPointInputBuilder::name)
    /// - [`regions`](crate::types::builders::CreateMultiRegionAccessPointInputBuilder::regions)
    pub fn build(self) -> ::std::result::Result<crate::types::CreateMultiRegionAccessPointInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::CreateMultiRegionAccessPointInput {
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building CreateMultiRegionAccessPointInput",
                )
            })?,
            public_access_block: self.public_access_block,
            regions: self.regions.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "regions",
                    "regions was not specified but it is required when building CreateMultiRegionAccessPointInput",
                )
            })?,
        })
    }
}
