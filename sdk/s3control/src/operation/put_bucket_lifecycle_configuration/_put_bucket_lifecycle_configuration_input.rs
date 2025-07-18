// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutBucketLifecycleConfigurationInput {
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub account_id: ::std::option::Option<::std::string::String>,
    /// <p>The name of the bucket for which to set the configuration.</p>
    pub bucket: ::std::option::Option<::std::string::String>,
    /// <p>Container for lifecycle rules. You can add as many as 1,000 rules.</p>
    pub lifecycle_configuration: ::std::option::Option<crate::types::LifecycleConfiguration>,
}
impl PutBucketLifecycleConfigurationInput {
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub fn account_id(&self) -> ::std::option::Option<&str> {
        self.account_id.as_deref()
    }
    /// <p>The name of the bucket for which to set the configuration.</p>
    pub fn bucket(&self) -> ::std::option::Option<&str> {
        self.bucket.as_deref()
    }
    /// <p>Container for lifecycle rules. You can add as many as 1,000 rules.</p>
    pub fn lifecycle_configuration(&self) -> ::std::option::Option<&crate::types::LifecycleConfiguration> {
        self.lifecycle_configuration.as_ref()
    }
}
impl PutBucketLifecycleConfigurationInput {
    /// Creates a new builder-style object to manufacture [`PutBucketLifecycleConfigurationInput`](crate::operation::put_bucket_lifecycle_configuration::PutBucketLifecycleConfigurationInput).
    pub fn builder() -> crate::operation::put_bucket_lifecycle_configuration::builders::PutBucketLifecycleConfigurationInputBuilder {
        crate::operation::put_bucket_lifecycle_configuration::builders::PutBucketLifecycleConfigurationInputBuilder::default()
    }
}

/// A builder for [`PutBucketLifecycleConfigurationInput`](crate::operation::put_bucket_lifecycle_configuration::PutBucketLifecycleConfigurationInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutBucketLifecycleConfigurationInputBuilder {
    pub(crate) account_id: ::std::option::Option<::std::string::String>,
    pub(crate) bucket: ::std::option::Option<::std::string::String>,
    pub(crate) lifecycle_configuration: ::std::option::Option<crate::types::LifecycleConfiguration>,
}
impl PutBucketLifecycleConfigurationInputBuilder {
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    /// This field is required.
    pub fn account_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.account_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub fn set_account_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.account_id = input;
        self
    }
    /// <p>The Amazon Web Services account ID of the Outposts bucket.</p>
    pub fn get_account_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.account_id
    }
    /// <p>The name of the bucket for which to set the configuration.</p>
    /// This field is required.
    pub fn bucket(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.bucket = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the bucket for which to set the configuration.</p>
    pub fn set_bucket(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.bucket = input;
        self
    }
    /// <p>The name of the bucket for which to set the configuration.</p>
    pub fn get_bucket(&self) -> &::std::option::Option<::std::string::String> {
        &self.bucket
    }
    /// <p>Container for lifecycle rules. You can add as many as 1,000 rules.</p>
    pub fn lifecycle_configuration(mut self, input: crate::types::LifecycleConfiguration) -> Self {
        self.lifecycle_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Container for lifecycle rules. You can add as many as 1,000 rules.</p>
    pub fn set_lifecycle_configuration(mut self, input: ::std::option::Option<crate::types::LifecycleConfiguration>) -> Self {
        self.lifecycle_configuration = input;
        self
    }
    /// <p>Container for lifecycle rules. You can add as many as 1,000 rules.</p>
    pub fn get_lifecycle_configuration(&self) -> &::std::option::Option<crate::types::LifecycleConfiguration> {
        &self.lifecycle_configuration
    }
    /// Consumes the builder and constructs a [`PutBucketLifecycleConfigurationInput`](crate::operation::put_bucket_lifecycle_configuration::PutBucketLifecycleConfigurationInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::put_bucket_lifecycle_configuration::PutBucketLifecycleConfigurationInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::put_bucket_lifecycle_configuration::PutBucketLifecycleConfigurationInput {
                account_id: self.account_id,
                bucket: self.bucket,
                lifecycle_configuration: self.lifecycle_configuration,
            },
        )
    }
}
