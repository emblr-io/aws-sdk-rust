// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The configuration information for the bucket.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBucketConfiguration {
    /// <p>Specifies the Region where the bucket will be created. You might choose a Region to optimize latency, minimize costs, or address regulatory requirements. For example, if you reside in Europe, you will probably find it advantageous to create buckets in the Europe (Ireland) Region.</p>
    /// <p>If you don't specify a Region, the bucket is created in the US East (N. Virginia) Region (us-east-1) by default. Configurations using the value <code>EU</code> will create a bucket in <code>eu-west-1</code>.</p>
    /// <p>For a list of the valid values for all of the Amazon Web Services Regions, see <a href="https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region">Regions and Endpoints</a>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub location_constraint: ::std::option::Option<crate::types::BucketLocationConstraint>,
    /// <p>Specifies the location where the bucket will be created.</p>
    /// <p><b>Directory buckets </b> - The location type is Availability Zone or Local Zone. To use the Local Zone location type, your account must be enabled for Local Zones. Otherwise, you get an HTTP <code>403 Forbidden</code> error with the error code <code>AccessDenied</code>. To learn more, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/opt-in-directory-bucket-lz.html">Enable accounts for Local Zones</a> in the <i>Amazon S3 User Guide</i>.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub location: ::std::option::Option<crate::types::LocationInfo>,
    /// <p>Specifies the information about the bucket that will be created.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub bucket: ::std::option::Option<crate::types::BucketInfo>,
    /// <p>An array of tags that you can apply to the bucket that you're creating. Tags are key-value pairs of metadata used to categorize and organize your buckets, track costs, and control access.</p><note>
    /// <p>This parameter is only supported for S3 directory buckets. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-tagging.html">Using tags with directory buckets</a>.</p>
    /// </note>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateBucketConfiguration {
    /// <p>Specifies the Region where the bucket will be created. You might choose a Region to optimize latency, minimize costs, or address regulatory requirements. For example, if you reside in Europe, you will probably find it advantageous to create buckets in the Europe (Ireland) Region.</p>
    /// <p>If you don't specify a Region, the bucket is created in the US East (N. Virginia) Region (us-east-1) by default. Configurations using the value <code>EU</code> will create a bucket in <code>eu-west-1</code>.</p>
    /// <p>For a list of the valid values for all of the Amazon Web Services Regions, see <a href="https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region">Regions and Endpoints</a>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn location_constraint(&self) -> ::std::option::Option<&crate::types::BucketLocationConstraint> {
        self.location_constraint.as_ref()
    }
    /// <p>Specifies the location where the bucket will be created.</p>
    /// <p><b>Directory buckets </b> - The location type is Availability Zone or Local Zone. To use the Local Zone location type, your account must be enabled for Local Zones. Otherwise, you get an HTTP <code>403 Forbidden</code> error with the error code <code>AccessDenied</code>. To learn more, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/opt-in-directory-bucket-lz.html">Enable accounts for Local Zones</a> in the <i>Amazon S3 User Guide</i>.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn location(&self) -> ::std::option::Option<&crate::types::LocationInfo> {
        self.location.as_ref()
    }
    /// <p>Specifies the information about the bucket that will be created.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn bucket(&self) -> ::std::option::Option<&crate::types::BucketInfo> {
        self.bucket.as_ref()
    }
    /// <p>An array of tags that you can apply to the bucket that you're creating. Tags are key-value pairs of metadata used to categorize and organize your buckets, track costs, and control access.</p><note>
    /// <p>This parameter is only supported for S3 directory buckets. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-tagging.html">Using tags with directory buckets</a>.</p>
    /// </note>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateBucketConfiguration {
    /// Creates a new builder-style object to manufacture [`CreateBucketConfiguration`](crate::types::CreateBucketConfiguration).
    pub fn builder() -> crate::types::builders::CreateBucketConfigurationBuilder {
        crate::types::builders::CreateBucketConfigurationBuilder::default()
    }
}

/// A builder for [`CreateBucketConfiguration`](crate::types::CreateBucketConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBucketConfigurationBuilder {
    pub(crate) location_constraint: ::std::option::Option<crate::types::BucketLocationConstraint>,
    pub(crate) location: ::std::option::Option<crate::types::LocationInfo>,
    pub(crate) bucket: ::std::option::Option<crate::types::BucketInfo>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateBucketConfigurationBuilder {
    /// <p>Specifies the Region where the bucket will be created. You might choose a Region to optimize latency, minimize costs, or address regulatory requirements. For example, if you reside in Europe, you will probably find it advantageous to create buckets in the Europe (Ireland) Region.</p>
    /// <p>If you don't specify a Region, the bucket is created in the US East (N. Virginia) Region (us-east-1) by default. Configurations using the value <code>EU</code> will create a bucket in <code>eu-west-1</code>.</p>
    /// <p>For a list of the valid values for all of the Amazon Web Services Regions, see <a href="https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region">Regions and Endpoints</a>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn location_constraint(mut self, input: crate::types::BucketLocationConstraint) -> Self {
        self.location_constraint = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the Region where the bucket will be created. You might choose a Region to optimize latency, minimize costs, or address regulatory requirements. For example, if you reside in Europe, you will probably find it advantageous to create buckets in the Europe (Ireland) Region.</p>
    /// <p>If you don't specify a Region, the bucket is created in the US East (N. Virginia) Region (us-east-1) by default. Configurations using the value <code>EU</code> will create a bucket in <code>eu-west-1</code>.</p>
    /// <p>For a list of the valid values for all of the Amazon Web Services Regions, see <a href="https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region">Regions and Endpoints</a>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn set_location_constraint(mut self, input: ::std::option::Option<crate::types::BucketLocationConstraint>) -> Self {
        self.location_constraint = input;
        self
    }
    /// <p>Specifies the Region where the bucket will be created. You might choose a Region to optimize latency, minimize costs, or address regulatory requirements. For example, if you reside in Europe, you will probably find it advantageous to create buckets in the Europe (Ireland) Region.</p>
    /// <p>If you don't specify a Region, the bucket is created in the US East (N. Virginia) Region (us-east-1) by default. Configurations using the value <code>EU</code> will create a bucket in <code>eu-west-1</code>.</p>
    /// <p>For a list of the valid values for all of the Amazon Web Services Regions, see <a href="https://docs.aws.amazon.com/general/latest/gr/rande.html#s3_region">Regions and Endpoints</a>.</p><note>
    /// <p>This functionality is not supported for directory buckets.</p>
    /// </note>
    pub fn get_location_constraint(&self) -> &::std::option::Option<crate::types::BucketLocationConstraint> {
        &self.location_constraint
    }
    /// <p>Specifies the location where the bucket will be created.</p>
    /// <p><b>Directory buckets </b> - The location type is Availability Zone or Local Zone. To use the Local Zone location type, your account must be enabled for Local Zones. Otherwise, you get an HTTP <code>403 Forbidden</code> error with the error code <code>AccessDenied</code>. To learn more, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/opt-in-directory-bucket-lz.html">Enable accounts for Local Zones</a> in the <i>Amazon S3 User Guide</i>.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn location(mut self, input: crate::types::LocationInfo) -> Self {
        self.location = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the location where the bucket will be created.</p>
    /// <p><b>Directory buckets </b> - The location type is Availability Zone or Local Zone. To use the Local Zone location type, your account must be enabled for Local Zones. Otherwise, you get an HTTP <code>403 Forbidden</code> error with the error code <code>AccessDenied</code>. To learn more, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/opt-in-directory-bucket-lz.html">Enable accounts for Local Zones</a> in the <i>Amazon S3 User Guide</i>.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn set_location(mut self, input: ::std::option::Option<crate::types::LocationInfo>) -> Self {
        self.location = input;
        self
    }
    /// <p>Specifies the location where the bucket will be created.</p>
    /// <p><b>Directory buckets </b> - The location type is Availability Zone or Local Zone. To use the Local Zone location type, your account must be enabled for Local Zones. Otherwise, you get an HTTP <code>403 Forbidden</code> error with the error code <code>AccessDenied</code>. To learn more, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/opt-in-directory-bucket-lz.html">Enable accounts for Local Zones</a> in the <i>Amazon S3 User Guide</i>.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn get_location(&self) -> &::std::option::Option<crate::types::LocationInfo> {
        &self.location
    }
    /// <p>Specifies the information about the bucket that will be created.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn bucket(mut self, input: crate::types::BucketInfo) -> Self {
        self.bucket = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the information about the bucket that will be created.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn set_bucket(mut self, input: ::std::option::Option<crate::types::BucketInfo>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>Specifies the information about the bucket that will be created.</p><note>
    /// <p>This functionality is only supported by directory buckets.</p>
    /// </note>
    pub fn get_bucket(&self) -> &::std::option::Option<crate::types::BucketInfo> {
        &self.bucket
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of tags that you can apply to the bucket that you're creating. Tags are key-value pairs of metadata used to categorize and organize your buckets, track costs, and control access.</p><note>
    /// <p>This parameter is only supported for S3 directory buckets. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-tagging.html">Using tags with directory buckets</a>.</p>
    /// </note>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of tags that you can apply to the bucket that you're creating. Tags are key-value pairs of metadata used to categorize and organize your buckets, track costs, and control access.</p><note>
    /// <p>This parameter is only supported for S3 directory buckets. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-tagging.html">Using tags with directory buckets</a>.</p>
    /// </note>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of tags that you can apply to the bucket that you're creating. Tags are key-value pairs of metadata used to categorize and organize your buckets, track costs, and control access.</p><note>
    /// <p>This parameter is only supported for S3 directory buckets. For more information, see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-tagging.html">Using tags with directory buckets</a>.</p>
    /// </note>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateBucketConfiguration`](crate::types::CreateBucketConfiguration).
    pub fn build(self) -> crate::types::CreateBucketConfiguration {
        crate::types::CreateBucketConfiguration {
            location_constraint: self.location_constraint,
            location: self.location,
            bucket: self.bucket,
            tags: self.tags,
        }
    }
}
