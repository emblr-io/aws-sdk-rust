// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the parameters for AddTags.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct AddTagsInput {
    /// <p>The ID of the pipeline.</p>
    pub pipeline_id: ::std::option::Option<::std::string::String>,
    /// <p>The tags to add, as key/value pairs.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AddTagsInput {
    /// <p>The ID of the pipeline.</p>
    pub fn pipeline_id(&self) -> ::std::option::Option<&str> {
        self.pipeline_id.as_deref()
    }
    /// <p>The tags to add, as key/value pairs.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl AddTagsInput {
    /// Creates a new builder-style object to manufacture [`AddTagsInput`](crate::operation::add_tags::AddTagsInput).
    pub fn builder() -> crate::operation::add_tags::builders::AddTagsInputBuilder {
        crate::operation::add_tags::builders::AddTagsInputBuilder::default()
    }
}

/// A builder for [`AddTagsInput`](crate::operation::add_tags::AddTagsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct AddTagsInputBuilder {
    pub(crate) pipeline_id: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl AddTagsInputBuilder {
    /// <p>The ID of the pipeline.</p>
    /// This field is required.
    pub fn pipeline_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.pipeline_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the pipeline.</p>
    pub fn set_pipeline_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.pipeline_id = input;
        self
    }
    /// <p>The ID of the pipeline.</p>
    pub fn get_pipeline_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.pipeline_id
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>The tags to add, as key/value pairs.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>The tags to add, as key/value pairs.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>The tags to add, as key/value pairs.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`AddTagsInput`](crate::operation::add_tags::AddTagsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::add_tags::AddTagsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::add_tags::AddTagsInput {
            pipeline_id: self.pipeline_id,
            tags: self.tags,
        })
    }
}
