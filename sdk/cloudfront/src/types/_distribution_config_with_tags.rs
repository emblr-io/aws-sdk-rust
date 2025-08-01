// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A distribution Configuration and a list of tags to be associated with the distribution.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DistributionConfigWithTags {
    /// <p>A distribution configuration.</p>
    pub distribution_config: ::std::option::Option<crate::types::DistributionConfig>,
    /// <p>A complex type that contains zero or more <code>Tag</code> elements.</p>
    pub tags: ::std::option::Option<crate::types::Tags>,
}
impl DistributionConfigWithTags {
    /// <p>A distribution configuration.</p>
    pub fn distribution_config(&self) -> ::std::option::Option<&crate::types::DistributionConfig> {
        self.distribution_config.as_ref()
    }
    /// <p>A complex type that contains zero or more <code>Tag</code> elements.</p>
    pub fn tags(&self) -> ::std::option::Option<&crate::types::Tags> {
        self.tags.as_ref()
    }
}
impl DistributionConfigWithTags {
    /// Creates a new builder-style object to manufacture [`DistributionConfigWithTags`](crate::types::DistributionConfigWithTags).
    pub fn builder() -> crate::types::builders::DistributionConfigWithTagsBuilder {
        crate::types::builders::DistributionConfigWithTagsBuilder::default()
    }
}

/// A builder for [`DistributionConfigWithTags`](crate::types::DistributionConfigWithTags).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DistributionConfigWithTagsBuilder {
    pub(crate) distribution_config: ::std::option::Option<crate::types::DistributionConfig>,
    pub(crate) tags: ::std::option::Option<crate::types::Tags>,
}
impl DistributionConfigWithTagsBuilder {
    /// <p>A distribution configuration.</p>
    /// This field is required.
    pub fn distribution_config(mut self, input: crate::types::DistributionConfig) -> Self {
        self.distribution_config = ::std::option::Option::Some(input);
        self
    }
    /// <p>A distribution configuration.</p>
    pub fn set_distribution_config(mut self, input: ::std::option::Option<crate::types::DistributionConfig>) -> Self {
        self.distribution_config = input;
        self
    }
    /// <p>A distribution configuration.</p>
    pub fn get_distribution_config(&self) -> &::std::option::Option<crate::types::DistributionConfig> {
        &self.distribution_config
    }
    /// <p>A complex type that contains zero or more <code>Tag</code> elements.</p>
    /// This field is required.
    pub fn tags(mut self, input: crate::types::Tags) -> Self {
        self.tags = ::std::option::Option::Some(input);
        self
    }
    /// <p>A complex type that contains zero or more <code>Tag</code> elements.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<crate::types::Tags>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A complex type that contains zero or more <code>Tag</code> elements.</p>
    pub fn get_tags(&self) -> &::std::option::Option<crate::types::Tags> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`DistributionConfigWithTags`](crate::types::DistributionConfigWithTags).
    pub fn build(self) -> crate::types::DistributionConfigWithTags {
        crate::types::DistributionConfigWithTags {
            distribution_config: self.distribution_config,
            tags: self.tags,
        }
    }
}
