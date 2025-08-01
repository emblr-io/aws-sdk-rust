// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateTagsInput {
    /// <p>The ID of the file system whose tags you want to modify (String). This operation modifies the tags only, not the file system.</p>
    pub file_system_id: ::std::option::Option<::std::string::String>,
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateTagsInput {
    /// <p>The ID of the file system whose tags you want to modify (String). This operation modifies the tags only, not the file system.</p>
    pub fn file_system_id(&self) -> ::std::option::Option<&str> {
        self.file_system_id.as_deref()
    }
    /// <p>An array of <code>Tag</code> objects to add. Each <code>Tag</code> object is a key-value pair.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl CreateTagsInput {
    /// Creates a new builder-style object to manufacture [`CreateTagsInput`](crate::operation::create_tags::CreateTagsInput).
    pub fn builder() -> crate::operation::create_tags::builders::CreateTagsInputBuilder {
        crate::operation::create_tags::builders::CreateTagsInputBuilder::default()
    }
}

/// A builder for [`CreateTagsInput`](crate::operation::create_tags::CreateTagsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateTagsInputBuilder {
    pub(crate) file_system_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl CreateTagsInputBuilder {
    /// <p>The ID of the file system whose tags you want to modify (String). This operation modifies the tags only, not the file system.</p>
    /// This field is required.
    pub fn file_system_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.file_system_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the file system whose tags you want to modify (String). This operation modifies the tags only, not the file system.</p>
    pub fn set_file_system_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.file_system_id = input;
        self
    }
    /// <p>The ID of the file system whose tags you want to modify (String). This operation modifies the tags only, not the file system.</p>
    pub fn get_file_system_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.file_system_id
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
    /// Consumes the builder and constructs a [`CreateTagsInput`](crate::operation::create_tags::CreateTagsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::create_tags::CreateTagsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_tags::CreateTagsInput {
            file_system_id: self.file_system_id,
            tags: self.tags,
        })
    }
}
