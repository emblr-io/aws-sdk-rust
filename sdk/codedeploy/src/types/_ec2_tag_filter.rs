// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about an EC2 tag filter.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Ec2TagFilter {
    /// <p>The tag filter key.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p>The tag filter value.</p>
    pub value: ::std::option::Option<::std::string::String>,
    /// <p>The tag filter type:</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_ONLY</code>: Key only.</p></li>
    /// <li>
    /// <p><code>VALUE_ONLY</code>: Value only.</p></li>
    /// <li>
    /// <p><code>KEY_AND_VALUE</code>: Key and value.</p></li>
    /// </ul>
    pub r#type: ::std::option::Option<crate::types::Ec2TagFilterType>,
}
impl Ec2TagFilter {
    /// <p>The tag filter key.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p>The tag filter value.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
    /// <p>The tag filter type:</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_ONLY</code>: Key only.</p></li>
    /// <li>
    /// <p><code>VALUE_ONLY</code>: Value only.</p></li>
    /// <li>
    /// <p><code>KEY_AND_VALUE</code>: Key and value.</p></li>
    /// </ul>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::Ec2TagFilterType> {
        self.r#type.as_ref()
    }
}
impl Ec2TagFilter {
    /// Creates a new builder-style object to manufacture [`Ec2TagFilter`](crate::types::Ec2TagFilter).
    pub fn builder() -> crate::types::builders::Ec2TagFilterBuilder {
        crate::types::builders::Ec2TagFilterBuilder::default()
    }
}

/// A builder for [`Ec2TagFilter`](crate::types::Ec2TagFilter).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct Ec2TagFilterBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::Ec2TagFilterType>,
}
impl Ec2TagFilterBuilder {
    /// <p>The tag filter key.</p>
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tag filter key.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p>The tag filter key.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p>The tag filter value.</p>
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The tag filter value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p>The tag filter value.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// <p>The tag filter type:</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_ONLY</code>: Key only.</p></li>
    /// <li>
    /// <p><code>VALUE_ONLY</code>: Value only.</p></li>
    /// <li>
    /// <p><code>KEY_AND_VALUE</code>: Key and value.</p></li>
    /// </ul>
    pub fn r#type(mut self, input: crate::types::Ec2TagFilterType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The tag filter type:</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_ONLY</code>: Key only.</p></li>
    /// <li>
    /// <p><code>VALUE_ONLY</code>: Value only.</p></li>
    /// <li>
    /// <p><code>KEY_AND_VALUE</code>: Key and value.</p></li>
    /// </ul>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::Ec2TagFilterType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The tag filter type:</p>
    /// <ul>
    /// <li>
    /// <p><code>KEY_ONLY</code>: Key only.</p></li>
    /// <li>
    /// <p><code>VALUE_ONLY</code>: Value only.</p></li>
    /// <li>
    /// <p><code>KEY_AND_VALUE</code>: Key and value.</p></li>
    /// </ul>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::Ec2TagFilterType> {
        &self.r#type
    }
    /// Consumes the builder and constructs a [`Ec2TagFilter`](crate::types::Ec2TagFilter).
    pub fn build(self) -> crate::types::Ec2TagFilter {
        crate::types::Ec2TagFilter {
            key: self.key,
            value: self.value,
            r#type: self.r#type,
        }
    }
}
