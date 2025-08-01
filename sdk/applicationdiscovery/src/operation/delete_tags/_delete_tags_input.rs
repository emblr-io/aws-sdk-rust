// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteTagsInput {
    /// <p>A list of configuration items with tags that you want to delete.</p>
    pub configuration_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Tags that you want to delete from one or more configuration items. Specify the tags that you want to delete in a <i>key</i>-<i>value</i> format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl DeleteTagsInput {
    /// <p>A list of configuration items with tags that you want to delete.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.configuration_ids.is_none()`.
    pub fn configuration_ids(&self) -> &[::std::string::String] {
        self.configuration_ids.as_deref().unwrap_or_default()
    }
    /// <p>Tags that you want to delete from one or more configuration items. Specify the tags that you want to delete in a <i>key</i>-<i>value</i> format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl DeleteTagsInput {
    /// Creates a new builder-style object to manufacture [`DeleteTagsInput`](crate::operation::delete_tags::DeleteTagsInput).
    pub fn builder() -> crate::operation::delete_tags::builders::DeleteTagsInputBuilder {
        crate::operation::delete_tags::builders::DeleteTagsInputBuilder::default()
    }
}

/// A builder for [`DeleteTagsInput`](crate::operation::delete_tags::DeleteTagsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteTagsInputBuilder {
    pub(crate) configuration_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl DeleteTagsInputBuilder {
    /// Appends an item to `configuration_ids`.
    ///
    /// To override the contents of this collection use [`set_configuration_ids`](Self::set_configuration_ids).
    ///
    /// <p>A list of configuration items with tags that you want to delete.</p>
    pub fn configuration_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.configuration_ids.unwrap_or_default();
        v.push(input.into());
        self.configuration_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of configuration items with tags that you want to delete.</p>
    pub fn set_configuration_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.configuration_ids = input;
        self
    }
    /// <p>A list of configuration items with tags that you want to delete.</p>
    pub fn get_configuration_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.configuration_ids
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>Tags that you want to delete from one or more configuration items. Specify the tags that you want to delete in a <i>key</i>-<i>value</i> format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>Tags that you want to delete from one or more configuration items. Specify the tags that you want to delete in a <i>key</i>-<i>value</i> format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>Tags that you want to delete from one or more configuration items. Specify the tags that you want to delete in a <i>key</i>-<i>value</i> format. For example:</p>
    /// <p><code>{"key": "serverType", "value": "webServer"}</code></p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`DeleteTagsInput`](crate::operation::delete_tags::DeleteTagsInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::delete_tags::DeleteTagsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::delete_tags::DeleteTagsInput {
            configuration_ids: self.configuration_ids,
            tags: self.tags,
        })
    }
}
