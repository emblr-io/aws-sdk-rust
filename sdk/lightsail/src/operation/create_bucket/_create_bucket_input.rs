// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateBucketInput {
    /// <p>The name for the bucket.</p>
    /// <p>For more information about bucket names, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/bucket-naming-rules-in-amazon-lightsail">Bucket naming rules in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub bucket_name: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the bundle to use for the bucket.</p>
    /// <p>A bucket bundle specifies the monthly cost, storage space, and data transfer quota for a bucket.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetBucketBundles.html">GetBucketBundles</a> action to get a list of bundle IDs that you can specify.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_UpdateBucketBundle.html">UpdateBucketBundle</a> action to change the bundle after the bucket is created.</p>
    pub bundle_id: ::std::option::Option<::std::string::String>,
    /// <p>The tag keys and optional values to add to the bucket during creation.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_TagResource.html">TagResource</a> action to tag the bucket after it's created.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    /// <p>A Boolean value that indicates whether to enable versioning of objects in the bucket.</p>
    /// <p>For more information about versioning, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-managing-bucket-object-versioning">Enabling and suspending object versioning in a bucket in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub enable_object_versioning: ::std::option::Option<bool>,
}
impl CreateBucketInput {
    /// <p>The name for the bucket.</p>
    /// <p>For more information about bucket names, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/bucket-naming-rules-in-amazon-lightsail">Bucket naming rules in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn bucket_name(&self) -> ::std::option::Option<&str> {
        self.bucket_name.as_deref()
    }
    /// <p>The ID of the bundle to use for the bucket.</p>
    /// <p>A bucket bundle specifies the monthly cost, storage space, and data transfer quota for a bucket.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetBucketBundles.html">GetBucketBundles</a> action to get a list of bundle IDs that you can specify.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_UpdateBucketBundle.html">UpdateBucketBundle</a> action to change the bundle after the bucket is created.</p>
    pub fn bundle_id(&self) -> ::std::option::Option<&str> {
        self.bundle_id.as_deref()
    }
    /// <p>The tag keys and optional values to add to the bucket during creation.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_TagResource.html">TagResource</a> action to tag the bucket after it's created.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
    /// <p>A Boolean value that indicates whether to enable versioning of objects in the bucket.</p>
    /// <p>For more information about versioning, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-managing-bucket-object-versioning">Enabling and suspending object versioning in a bucket in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn enable_object_versioning(&self) -> ::std::option::Option<bool> {
        self.enable_object_versioning
    }
}
impl CreateBucketInput {
    /// Creates a new builder-style object to manufacture [`CreateBucketInput`](crate::operation::create_bucket::CreateBucketInput).
    pub fn builder() -> crate::operation::create_bucket::builders::CreateBucketInputBuilder {
        crate::operation::create_bucket::builders::CreateBucketInputBuilder::default()
    }
}

/// A builder for [`CreateBucketInput`](crate::operation::create_bucket::CreateBucketInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateBucketInputBuilder {
    pub(crate) bucket_name: ::std::option::Option<::std::string::String>,
    pub(crate) bundle_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
    pub(crate) enable_object_versioning: ::std::option::Option<bool>,
}
impl CreateBucketInputBuilder {
    /// <p>The name for the bucket.</p>
    /// <p>For more information about bucket names, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/bucket-naming-rules-in-amazon-lightsail">Bucket naming rules in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    /// This field is required.
    pub fn bucket_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name for the bucket.</p>
    /// <p>For more information about bucket names, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/bucket-naming-rules-in-amazon-lightsail">Bucket naming rules in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn set_bucket_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket_name = input;
        self
    }
    /// <p>The name for the bucket.</p>
    /// <p>For more information about bucket names, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/bucket-naming-rules-in-amazon-lightsail">Bucket naming rules in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn get_bucket_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket_name
    }
    /// <p>The ID of the bundle to use for the bucket.</p>
    /// <p>A bucket bundle specifies the monthly cost, storage space, and data transfer quota for a bucket.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetBucketBundles.html">GetBucketBundles</a> action to get a list of bundle IDs that you can specify.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_UpdateBucketBundle.html">UpdateBucketBundle</a> action to change the bundle after the bucket is created.</p>
    /// This field is required.
    pub fn bundle_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bundle_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the bundle to use for the bucket.</p>
    /// <p>A bucket bundle specifies the monthly cost, storage space, and data transfer quota for a bucket.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetBucketBundles.html">GetBucketBundles</a> action to get a list of bundle IDs that you can specify.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_UpdateBucketBundle.html">UpdateBucketBundle</a> action to change the bundle after the bucket is created.</p>
    pub fn set_bundle_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bundle_id = input;
        self
    }
    /// <p>The ID of the bundle to use for the bucket.</p>
    /// <p>A bucket bundle specifies the monthly cost, storage space, and data transfer quota for a bucket.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_GetBucketBundles.html">GetBucketBundles</a> action to get a list of bundle IDs that you can specify.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_UpdateBucketBundle.html">UpdateBucketBundle</a> action to change the bundle after the bucket is created.</p>
    pub fn get_bundle_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.bundle_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tag keys and optional values to add to the bucket during creation.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_TagResource.html">TagResource</a> action to tag the bucket after it's created.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tag keys and optional values to add to the bucket during creation.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_TagResource.html">TagResource</a> action to tag the bucket after it's created.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tag keys and optional values to add to the bucket during creation.</p>
    /// <p>Use the <a href="https://docs.aws.amazon.com/lightsail/2016-11-28/api-reference/API_TagResource.html">TagResource</a> action to tag the bucket after it's created.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// <p>A Boolean value that indicates whether to enable versioning of objects in the bucket.</p>
    /// <p>For more information about versioning, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-managing-bucket-object-versioning">Enabling and suspending object versioning in a bucket in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn enable_object_versioning(mut self, input: bool) -> Self {
        self.enable_object_versioning = ::std::option::Option::Some(input);
        self
    }
    /// <p>A Boolean value that indicates whether to enable versioning of objects in the bucket.</p>
    /// <p>For more information about versioning, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-managing-bucket-object-versioning">Enabling and suspending object versioning in a bucket in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn set_enable_object_versioning(mut self, input: ::std::option::Option<bool>) -> Self {
        self.enable_object_versioning = input;
        self
    }
    /// <p>A Boolean value that indicates whether to enable versioning of objects in the bucket.</p>
    /// <p>For more information about versioning, see <a href="https://docs.aws.amazon.com/lightsail/latest/userguide/amazon-lightsail-managing-bucket-object-versioning">Enabling and suspending object versioning in a bucket in Amazon Lightsail</a> in the <i>Amazon Lightsail Developer Guide</i>.</p>
    pub fn get_enable_object_versioning(&self) -> &::std::option::Option<bool> {
        &self.enable_object_versioning
    }
    /// Consumes the builder and constructs a [`CreateBucketInput`](crate::operation::create_bucket::CreateBucketInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_bucket::CreateBucketInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_bucket::CreateBucketInput {
            bucket_name: self.bucket_name,
            bundle_id: self.bundle_id,
            tags: self.tags,
            enable_object_versioning: self.enable_object_versioning,
        })
    }
}
