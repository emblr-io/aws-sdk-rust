// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input of a <code>CreateCacheSecurityGroup</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateCacheSecurityGroupInput {
    /// <p>A name for the cache security group. This value is stored as a lowercase string.</p>
    /// <p>Constraints: Must contain no more than 255 alphanumeric characters. Cannot be the word "Default".</p>
    /// <p>Example: <code>mysecuritygroup</code></p>
    pub cache_security_group_name: ::std::option::Option<::std::string::String>,
    /// <p>A description for the cache security group.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateCacheSecurityGroupInput {
    /// <p>A name for the cache security group. This value is stored as a lowercase string.</p>
    /// <p>Constraints: Must contain no more than 255 alphanumeric characters. Cannot be the word "Default".</p>
    /// <p>Example: <code>mysecuritygroup</code></p>
    pub fn cache_security_group_name(&self) -> ::std::option::Option<&str> {
        self.cache_security_group_name.as_deref()
    }
    /// <p>A description for the cache security group.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateCacheSecurityGroupInput {
    /// Creates a new builder-style object to manufacture [`CreateCacheSecurityGroupInput`](crate::operation::create_cache_security_group::CreateCacheSecurityGroupInput).
    pub fn builder() -> crate::operation::create_cache_security_group::builders::CreateCacheSecurityGroupInputBuilder {
        crate::operation::create_cache_security_group::builders::CreateCacheSecurityGroupInputBuilder::default()
    }
}

/// A builder for [`CreateCacheSecurityGroupInput`](crate::operation::create_cache_security_group::CreateCacheSecurityGroupInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateCacheSecurityGroupInputBuilder {
    pub(crate) cache_security_group_name: ::std::option::Option<::std::string::String>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateCacheSecurityGroupInputBuilder {
    /// <p>A name for the cache security group. This value is stored as a lowercase string.</p>
    /// <p>Constraints: Must contain no more than 255 alphanumeric characters. Cannot be the word "Default".</p>
    /// <p>Example: <code>mysecuritygroup</code></p>
    /// This field is required.
    pub fn cache_security_group_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.cache_security_group_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name for the cache security group. This value is stored as a lowercase string.</p>
    /// <p>Constraints: Must contain no more than 255 alphanumeric characters. Cannot be the word "Default".</p>
    /// <p>Example: <code>mysecuritygroup</code></p>
    pub fn set_cache_security_group_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.cache_security_group_name = input;
        self
    }
    /// <p>A name for the cache security group. This value is stored as a lowercase string.</p>
    /// <p>Constraints: Must contain no more than 255 alphanumeric characters. Cannot be the word "Default".</p>
    /// <p>Example: <code>mysecuritygroup</code></p>
    pub fn get_cache_security_group_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.cache_security_group_name
    }
    /// <p>A description for the cache security group.</p>
    /// This field is required.
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A description for the cache security group.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>A description for the cache security group.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A list of tags to be added to this resource. A tag is a key-value pair. A tag key must be accompanied by a tag value, although null is accepted.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateCacheSecurityGroupInput`](crate::operation::create_cache_security_group::CreateCacheSecurityGroupInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::create_cache_security_group::CreateCacheSecurityGroupInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::create_cache_security_group::CreateCacheSecurityGroupInput {
            cache_security_group_name: self.cache_security_group_name,
            description: self.description,
            tags: self.tags,
        })
    }
}
