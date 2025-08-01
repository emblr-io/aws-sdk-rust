// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The Tag type enables you to specify a key-value pair that can be used to store information about an CloudFormation stack.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Tag {
    /// <p><i>Required</i>. A string used to identify this tag. You can specify a maximum of 128 characters for a tag key. Tags owned by Amazon Web Services have the reserved prefix: <code>aws:</code>.</p>
    pub key: ::std::option::Option<::std::string::String>,
    /// <p><i>Required</i>. A string that contains the value for this tag. You can specify a maximum of 256 characters for a tag value.</p>
    pub value: ::std::option::Option<::std::string::String>,
}
impl Tag {
    /// <p><i>Required</i>. A string used to identify this tag. You can specify a maximum of 128 characters for a tag key. Tags owned by Amazon Web Services have the reserved prefix: <code>aws:</code>.</p>
    pub fn key(&self) -> ::std::option::Option<&str> {
        self.key.as_deref()
    }
    /// <p><i>Required</i>. A string that contains the value for this tag. You can specify a maximum of 256 characters for a tag value.</p>
    pub fn value(&self) -> ::std::option::Option<&str> {
        self.value.as_deref()
    }
}
impl Tag {
    /// Creates a new builder-style object to manufacture [`Tag`](crate::types::Tag).
    pub fn builder() -> crate::types::builders::TagBuilder {
        crate::types::builders::TagBuilder::default()
    }
}

/// A builder for [`Tag`](crate::types::Tag).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagBuilder {
    pub(crate) key: ::std::option::Option<::std::string::String>,
    pub(crate) value: ::std::option::Option<::std::string::String>,
}
impl TagBuilder {
    /// <p><i>Required</i>. A string used to identify this tag. You can specify a maximum of 128 characters for a tag key. Tags owned by Amazon Web Services have the reserved prefix: <code>aws:</code>.</p>
    /// This field is required.
    pub fn key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><i>Required</i>. A string used to identify this tag. You can specify a maximum of 128 characters for a tag key. Tags owned by Amazon Web Services have the reserved prefix: <code>aws:</code>.</p>
    pub fn set_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.key = input;
        self
    }
    /// <p><i>Required</i>. A string used to identify this tag. You can specify a maximum of 128 characters for a tag key. Tags owned by Amazon Web Services have the reserved prefix: <code>aws:</code>.</p>
    pub fn get_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.key
    }
    /// <p><i>Required</i>. A string that contains the value for this tag. You can specify a maximum of 256 characters for a tag value.</p>
    /// This field is required.
    pub fn value(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.value = ::std::option::Option::Some(input.into());
        self
    }
    /// <p><i>Required</i>. A string that contains the value for this tag. You can specify a maximum of 256 characters for a tag value.</p>
    pub fn set_value(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.value = input;
        self
    }
    /// <p><i>Required</i>. A string that contains the value for this tag. You can specify a maximum of 256 characters for a tag value.</p>
    pub fn get_value(&self) -> &::std::option::Option<::std::string::String> {
        &self.value
    }
    /// Consumes the builder and constructs a [`Tag`](crate::types::Tag).
    pub fn build(self) -> crate::types::Tag {
        crate::types::Tag {
            key: self.key,
            value: self.value,
        }
    }
}
