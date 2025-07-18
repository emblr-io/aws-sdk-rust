// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A value to use for the filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails {
    /// <p>Prefix text for matching objects.</p>
    pub prefix: ::std::option::Option<::std::string::String>,
    /// <p>A tag that is assigned to matching objects.</p>
    pub tag: ::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails>,
    /// <p>The type of filter value. Valid values are <code>LifecyclePrefixPredicate</code> or <code>LifecycleTagPredicate</code>.</p>
    pub r#type: ::std::option::Option<::std::string::String>,
}
impl AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails {
    /// <p>Prefix text for matching objects.</p>
    pub fn prefix(&self) -> ::std::option::Option<&str> {
        self.prefix.as_deref()
    }
    /// <p>A tag that is assigned to matching objects.</p>
    pub fn tag(&self) -> ::std::option::Option<&crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails> {
        self.tag.as_ref()
    }
    /// <p>The type of filter value. Valid values are <code>LifecyclePrefixPredicate</code> or <code>LifecycleTagPredicate</code>.</p>
    pub fn r#type(&self) -> ::std::option::Option<&str> {
        self.r#type.as_deref()
    }
}
impl AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails {
    /// Creates a new builder-style object to manufacture [`AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails).
    pub fn builder() -> crate::types::builders::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetailsBuilder {
        crate::types::builders::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetailsBuilder::default()
    }
}

/// A builder for [`AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetailsBuilder {
    pub(crate) prefix: ::std::option::Option<::std::string::String>,
    pub(crate) tag: ::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails>,
    pub(crate) r#type: ::std::option::Option<::std::string::String>,
}
impl AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetailsBuilder {
    /// <p>Prefix text for matching objects.</p>
    pub fn prefix(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.prefix = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Prefix text for matching objects.</p>
    pub fn set_prefix(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.prefix = input;
        self
    }
    /// <p>Prefix text for matching objects.</p>
    pub fn get_prefix(&self) -> &::std::option::Option<::std::string::String> {
        &self.prefix
    }
    /// <p>A tag that is assigned to matching objects.</p>
    pub fn tag(mut self, input: crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails) -> Self {
        self.tag = ::std::option::Option::Some(input);
        self
    }
    /// <p>A tag that is assigned to matching objects.</p>
    pub fn set_tag(
        mut self,
        input: ::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails>,
    ) -> Self {
        self.tag = input;
        self
    }
    /// <p>A tag that is assigned to matching objects.</p>
    pub fn get_tag(&self) -> &::std::option::Option<crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsTagDetails> {
        &self.tag
    }
    /// <p>The type of filter value. Valid values are <code>LifecyclePrefixPredicate</code> or <code>LifecycleTagPredicate</code>.</p>
    pub fn r#type(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.r#type = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The type of filter value. Valid values are <code>LifecyclePrefixPredicate</code> or <code>LifecycleTagPredicate</code>.</p>
    pub fn set_type(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of filter value. Valid values are <code>LifecyclePrefixPredicate</code> or <code>LifecycleTagPredicate</code>.</p>
    pub fn get_type(&self) -> &::std::option::Option<::std::string::String> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails`](crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails).
    pub fn build(self) -> crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails {
        crate::types::AwsS3BucketBucketLifecycleConfigurationRulesFilterPredicateOperandsDetails {
            prefix: self.prefix,
            tag: self.tag,
            r#type: self.r#type,
        }
    }
}
