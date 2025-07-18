// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagResourceInput {
    /// <p>The ID specifying the EFS resource that you want to create a tag for.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagResourceInput {
    /// <p>The ID specifying the EFS resource that you want to create a tag for.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl TagResourceInput {
    /// Creates a new builder-style object to manufacture [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
    pub fn builder() -> crate::operation::tag_resource::builders::TagResourceInputBuilder {
        crate::operation::tag_resource::builders::TagResourceInputBuilder::default()
    }
}

/// A builder for [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagResourceInputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagResourceInputBuilder {
    /// <p>The ID specifying the EFS resource that you want to create a tag for.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID specifying the EFS resource that you want to create a tag for.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The ID specifying the EFS resource that you want to create a tag for.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`TagResourceInput`](crate::operation::tag_resource::TagResourceInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::tag_resource::TagResourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::tag_resource::TagResourceInput {
            resource_id: self.resource_id,
            tags: self.tags,
        })
    }
}
