// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketIntelligentTieringConfigurationInput {
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub expected_bucket_owner: ::std::option::Option<::std::string::String>,
    /// <p>Container for S3 Intelligent-Tiering configuration.</p>
    pub intelligent_tiering_configuration: ::std::option::Option<crate::types::IntelligentTieringConfiguration>,
}
impl PutBucketIntelligentTieringConfigurationInput {
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(&self) -> ::std::option::Option<&str> {
        self.expected_bucket_owner.as_deref()
    }
    /// <p>Container for S3 Intelligent-Tiering configuration.</p>
    pub fn intelligent_tiering_configuration(&self) -> ::std::option::Option<&crate::types::IntelligentTieringConfiguration> {
        self.intelligent_tiering_configuration.as_ref()
    }
}
impl PutBucketIntelligentTieringConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutBucketIntelligentTieringConfigurationInput`](crate::operation::put_bucket_intelligent_tiering_configuration::PutBucketIntelligentTieringConfigurationInput).
    pub fn builder() -> crate::operation::put_bucket_intelligent_tiering_configuration::builders::PutBucketIntelligentTieringConfigurationInputBuilder
    {
        crate::operation::put_bucket_intelligent_tiering_configuration::builders::PutBucketIntelligentTieringConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutBucketIntelligentTieringConfigurationInput`](crate::operation::put_bucket_intelligent_tiering_configuration::PutBucketIntelligentTieringConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBucketIntelligentTieringConfigurationInputBuilder {
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) expected_bucket_owner: ::std::option::Option<::std::string::String>,
    pub(crate) intelligent_tiering_configuration: ::std::option::Option<crate::types::IntelligentTieringConfiguration>,
}
impl PutBucketIntelligentTieringConfigurationInputBuilder {
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the Amazon S3 bucket whose configuration you want to modify or retrieve.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID used to identify the S3 Intelligent-Tiering configuration.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn expected_bucket_owner(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.expected_bucket_owner = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn set_expected_bucket_owner(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.expected_bucket_owner = input;
        self
    }
    /// <p>The account ID of the expected bucket owner. If the account ID that you provide does not match the actual owner of the bucket, the request fails with the HTTP status code <code>403 Forbidden</code> (access denied).</p>
    pub fn get_expected_bucket_owner(&self) -> &::std::option::Option<::std::string::String> {
        &self.expected_bucket_owner
    }
    /// <p>Container for S3 Intelligent-Tiering configuration.</p>
    /// This field is required.
    pub fn intelligent_tiering_configuration(mut self, input: crate::types::IntelligentTieringConfiguration) -> Self {
        self.intelligent_tiering_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Container for S3 Intelligent-Tiering configuration.</p>
    pub fn set_intelligent_tiering_configuration(mut self, input: ::std::option::Option<crate::types::IntelligentTieringConfiguration>) -> Self {
        self.intelligent_tiering_configuration = input;
        self
    }
    /// <p>Container for S3 Intelligent-Tiering configuration.</p>
    pub fn get_intelligent_tiering_configuration(&self) -> &::std::option::Option<crate::types::IntelligentTieringConfiguration> {
        &self.intelligent_tiering_configuration
    }
    /// Consumes the builder and constructs a [`PutBucketIntelligentTieringConfigurationInput`](crate::operation::put_bucket_intelligent_tiering_configuration::PutBucketIntelligentTieringConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_bucket_intelligent_tiering_configuration::PutBucketIntelligentTieringConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_bucket_intelligent_tiering_configuration::PutBucketIntelligentTieringConfigurationInput {
                bucket: self.bucket,
                id: self.id,
                expected_bucket_owner: self.expected_bucket_owner,
                intelligent_tiering_configuration: self.intelligent_tiering_configuration,
            },
        )
    }
}
