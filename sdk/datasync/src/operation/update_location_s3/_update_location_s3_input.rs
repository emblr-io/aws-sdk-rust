// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateLocationS3Input {
    /// <p>Specifies the Amazon Resource Name (ARN) of the Amazon S3 transfer location that you're updating.</p>
    pub location_arn: ::std::option::Option<::std::string::String>,
    /// <p>Specifies a prefix in the S3 bucket that DataSync reads from or writes to (depending on whether the bucket is a source or destination location).</p><note>
    /// <p>DataSync can't transfer objects with a prefix that begins with a slash (<code>/</code>) or includes <code>//</code>, <code>/./</code>, or <code>/../</code> patterns. For example:</p>
    /// <ul>
    /// <li>
    /// <p><code>/photos</code></p></li>
    /// <li>
    /// <p><code>photos//2006/January</code></p></li>
    /// <li>
    /// <p><code>photos/./2006/February</code></p></li>
    /// <li>
    /// <p><code>photos/../2006/March</code></p></li>
    /// </ul>
    /// </note>
    pub subdirectory: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the storage class that you want your objects to use when Amazon S3 is a transfer destination.</p>
    /// <p>For buckets in Amazon Web Services Regions, the storage class defaults to <code>STANDARD</code>. For buckets on Outposts, the storage class defaults to <code>OUTPOSTS</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#using-storage-classes">Storage class considerations with Amazon S3 transfers</a>.</p>
    pub s3_storage_class: ::std::option::Option<crate::types::S3StorageClass>,
    /// <p>Specifies the Amazon Resource Name (ARN) of the Identity and Access Management (IAM) role that DataSync uses to access your S3 bucket.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#create-s3-location-access">Providing DataSync access to S3 buckets</a>.</p>
    pub s3_config: ::std::option::Option<crate::types::S3Config>,
}
impl UpdateLocationS3Input {
    /// <p>Specifies the Amazon Resource Name (ARN) of the Amazon S3 transfer location that you're updating.</p>
    pub fn location_arn(&self) -> ::std::option::Option<&str> {
        self.location_arn.as_deref()
    }
    /// <p>Specifies a prefix in the S3 bucket that DataSync reads from or writes to (depending on whether the bucket is a source or destination location).</p><note>
    /// <p>DataSync can't transfer objects with a prefix that begins with a slash (<code>/</code>) or includes <code>//</code>, <code>/./</code>, or <code>/../</code> patterns. For example:</p>
    /// <ul>
    /// <li>
    /// <p><code>/photos</code></p></li>
    /// <li>
    /// <p><code>photos//2006/January</code></p></li>
    /// <li>
    /// <p><code>photos/./2006/February</code></p></li>
    /// <li>
    /// <p><code>photos/../2006/March</code></p></li>
    /// </ul>
    /// </note>
    pub fn subdirectory(&self) -> ::std::option::Option<&str> {
        self.subdirectory.as_deref()
    }
    /// <p>Specifies the storage class that you want your objects to use when Amazon S3 is a transfer destination.</p>
    /// <p>For buckets in Amazon Web Services Regions, the storage class defaults to <code>STANDARD</code>. For buckets on Outposts, the storage class defaults to <code>OUTPOSTS</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#using-storage-classes">Storage class considerations with Amazon S3 transfers</a>.</p>
    pub fn s3_storage_class(&self) -> ::std::option::Option<&crate::types::S3StorageClass> {
        self.s3_storage_class.as_ref()
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the Identity and Access Management (IAM) role that DataSync uses to access your S3 bucket.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#create-s3-location-access">Providing DataSync access to S3 buckets</a>.</p>
    pub fn s3_config(&self) -> ::std::option::Option<&crate::types::S3Config> {
        self.s3_config.as_ref()
    }
}
impl UpdateLocationS3Input {
    /// Creates a new builder-style object to manufacture [`UpdateLocationS3Input`](crate::operation::update_location_s3::UpdateLocationS3Input).
    pub fn builder() -> crate::operation::update_location_s3::builders::UpdateLocationS3InputBuilder {
        crate::operation::update_location_s3::builders::UpdateLocationS3InputBuilder::default()
    }
}

/// A builder for [`UpdateLocationS3Input`](crate::operation::update_location_s3::UpdateLocationS3Input).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateLocationS3InputBuilder {
    pub(crate) location_arn: ::std::option::Option<::std::string::String>,
    pub(crate) subdirectory: ::std::option::Option<::std::string::String>,
    pub(crate) s3_storage_class: ::std::option::Option<crate::types::S3StorageClass>,
    pub(crate) s3_config: ::std::option::Option<crate::types::S3Config>,
}
impl UpdateLocationS3InputBuilder {
    /// <p>Specifies the Amazon Resource Name (ARN) of the Amazon S3 transfer location that you're updating.</p>
    /// This field is required.
    pub fn location_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the Amazon S3 transfer location that you're updating.</p>
    pub fn set_location_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location_arn = input;
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the Amazon S3 transfer location that you're updating.</p>
    pub fn get_location_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.location_arn
    }
    /// <p>Specifies a prefix in the S3 bucket that DataSync reads from or writes to (depending on whether the bucket is a source or destination location).</p><note>
    /// <p>DataSync can't transfer objects with a prefix that begins with a slash (<code>/</code>) or includes <code>//</code>, <code>/./</code>, or <code>/../</code> patterns. For example:</p>
    /// <ul>
    /// <li>
    /// <p><code>/photos</code></p></li>
    /// <li>
    /// <p><code>photos//2006/January</code></p></li>
    /// <li>
    /// <p><code>photos/./2006/February</code></p></li>
    /// <li>
    /// <p><code>photos/../2006/March</code></p></li>
    /// </ul>
    /// </note>
    pub fn subdirectory(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.subdirectory = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Specifies a prefix in the S3 bucket that DataSync reads from or writes to (depending on whether the bucket is a source or destination location).</p><note>
    /// <p>DataSync can't transfer objects with a prefix that begins with a slash (<code>/</code>) or includes <code>//</code>, <code>/./</code>, or <code>/../</code> patterns. For example:</p>
    /// <ul>
    /// <li>
    /// <p><code>/photos</code></p></li>
    /// <li>
    /// <p><code>photos//2006/January</code></p></li>
    /// <li>
    /// <p><code>photos/./2006/February</code></p></li>
    /// <li>
    /// <p><code>photos/../2006/March</code></p></li>
    /// </ul>
    /// </note>
    pub fn set_subdirectory(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.subdirectory = input;
        self
    }
    /// <p>Specifies a prefix in the S3 bucket that DataSync reads from or writes to (depending on whether the bucket is a source or destination location).</p><note>
    /// <p>DataSync can't transfer objects with a prefix that begins with a slash (<code>/</code>) or includes <code>//</code>, <code>/./</code>, or <code>/../</code> patterns. For example:</p>
    /// <ul>
    /// <li>
    /// <p><code>/photos</code></p></li>
    /// <li>
    /// <p><code>photos//2006/January</code></p></li>
    /// <li>
    /// <p><code>photos/./2006/February</code></p></li>
    /// <li>
    /// <p><code>photos/../2006/March</code></p></li>
    /// </ul>
    /// </note>
    pub fn get_subdirectory(&self) -> &::std::option::Option<::std::string::String> {
        &self.subdirectory
    }
    /// <p>Specifies the storage class that you want your objects to use when Amazon S3 is a transfer destination.</p>
    /// <p>For buckets in Amazon Web Services Regions, the storage class defaults to <code>STANDARD</code>. For buckets on Outposts, the storage class defaults to <code>OUTPOSTS</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#using-storage-classes">Storage class considerations with Amazon S3 transfers</a>.</p>
    pub fn s3_storage_class(mut self, input: crate::types::S3StorageClass) -> Self {
        self.s3_storage_class = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the storage class that you want your objects to use when Amazon S3 is a transfer destination.</p>
    /// <p>For buckets in Amazon Web Services Regions, the storage class defaults to <code>STANDARD</code>. For buckets on Outposts, the storage class defaults to <code>OUTPOSTS</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#using-storage-classes">Storage class considerations with Amazon S3 transfers</a>.</p>
    pub fn set_s3_storage_class(mut self, input: ::std::option::Option<crate::types::S3StorageClass>) -> Self {
        self.s3_storage_class = input;
        self
    }
    /// <p>Specifies the storage class that you want your objects to use when Amazon S3 is a transfer destination.</p>
    /// <p>For buckets in Amazon Web Services Regions, the storage class defaults to <code>STANDARD</code>. For buckets on Outposts, the storage class defaults to <code>OUTPOSTS</code>.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#using-storage-classes">Storage class considerations with Amazon S3 transfers</a>.</p>
    pub fn get_s3_storage_class(&self) -> &::std::option::Option<crate::types::S3StorageClass> {
        &self.s3_storage_class
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the Identity and Access Management (IAM) role that DataSync uses to access your S3 bucket.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#create-s3-location-access">Providing DataSync access to S3 buckets</a>.</p>
    pub fn s3_config(mut self, input: crate::types::S3Config) -> Self {
        self.s3_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the Identity and Access Management (IAM) role that DataSync uses to access your S3 bucket.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#create-s3-location-access">Providing DataSync access to S3 buckets</a>.</p>
    pub fn set_s3_config(mut self, input: ::std::option::Option<crate::types::S3Config>) -> Self {
        self.s3_config = input;
        self
    }
    /// <p>Specifies the Amazon Resource Name (ARN) of the Identity and Access Management (IAM) role that DataSync uses to access your S3 bucket.</p>
    /// <p>For more information, see <a href="https://docs.aws.amazon.com/datasync/latest/userguide/create-s3-location.html#create-s3-location-access">Providing DataSync access to S3 buckets</a>.</p>
    pub fn get_s3_config(&self) -> &::std::option::Option<crate::types::S3Config> {
        &self.s3_config
    }
    /// Consumes the builder and constructs a [`UpdateLocationS3Input`](crate::operation::update_location_s3::UpdateLocationS3Input).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::update_location_s3::UpdateLocationS3Input, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::update_location_s3::UpdateLocationS3Input {
            location_arn: self.location_arn,
            subdirectory: self.subdirectory,
            s3_storage_class: self.s3_storage_class,
            s3_config: self.s3_config,
        })
    }
}
