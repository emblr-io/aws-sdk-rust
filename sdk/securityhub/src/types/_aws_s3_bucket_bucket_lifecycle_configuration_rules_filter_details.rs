// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Identifies the objects that a rule applies to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails {
    /// <p>The configuration for the filter.</p>
    pub predicate: ::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails>,
}
impl AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails {
    /// <p>The configuration for the filter.</p>
    pub fn predicate(&self) -> ::std::option::Option<&crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails> {
        self.predicate.as_ref()
    }
}
impl AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails {
    /// Creates a new builder-style object to manufacture [`AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails).
    pub fn builder() -> crate::types::builders::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetailsBuilder {
        crate::types::builders::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetailsBuilder::default()
    }
}

/// A builder for [`AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsS3BucketBucketLifecycleConfigurationRulesFilterDetailsBuilder {
    pub(crate) predicate: ::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails>,
}
impl AwsS3BucketBucketLifecycleConfigurationRulesFilterDetailsBuilder {
    /// <p>The configuration for the filter.</p>
    pub fn predicate(mut self, input: crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails) -> Self {
        self.predicate = ::std::option::Option::Some(input);
        self
    }
    /// <p>The configuration for the filter.</p>
    pub fn set_predicate(
        mut self,
        input: ::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails>,
    ) -> Self {
        self.predicate = input;
        self
    }
    /// <p>The configuration for the filter.</p>
    pub fn get_predicate(&self) -> &::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateDetails> {
        &self.predicate
    }
    /// Consumes the builder and constructs a [`AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails).
    pub fn build(self) -> crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails {
        crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterDetails { predicate: self.predicate }
    }
}
