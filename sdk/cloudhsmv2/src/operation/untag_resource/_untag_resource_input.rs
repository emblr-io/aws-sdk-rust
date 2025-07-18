// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UntagResourceInput {
    /// <p>The cluster identifier (ID) for the cluster whose tags you are removing. To find the cluster ID, use <code>DescribeClusters</code>.</p>
    pub resource_id: ::std::option::Option<::std::string::String>,
    /// <p>A list of one or more tag keys for the tags that you are removing. Specify only the tag keys, not the tag values.</p>
    pub tag_key_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UntagResourceInput {
    /// <p>The cluster identifier (ID) for the cluster whose tags you are removing. To find the cluster ID, use <code>DescribeClusters</code>.</p>
    pub fn resource_id(&self) -> ::std::option::Option<&str> {
        self.resource_id.as_deref()
    }
    /// <p>A list of one or more tag keys for the tags that you are removing. Specify only the tag keys, not the tag values.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tag_key_list.is_none()`.
    pub fn tag_key_list(&self) -> &[::std::string::String] {
        self.tag_key_list.as_deref().unwrap_or_default()
    }
}
impl UntagResourceInput {
    /// Creates a new builder-style object to manufacture [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
    pub fn builder() -> crate::operation::untag_resource::builders::UntagResourceInputBuilder {
        crate::operation::untag_resource::builders::UntagResourceInputBuilder::default()
    }
}

/// A builder for [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UntagResourceInputBuilder {
    pub(crate) resource_id: ::std::option::Option<::std::string::String>,
    pub(crate) tag_key_list: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl UntagResourceInputBuilder {
    /// <p>The cluster identifier (ID) for the cluster whose tags you are removing. To find the cluster ID, use <code>DescribeClusters</code>.</p>
    /// This field is required.
    pub fn resource_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.resource_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The cluster identifier (ID) for the cluster whose tags you are removing. To find the cluster ID, use <code>DescribeClusters</code>.</p>
    pub fn set_resource_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.resource_id = input;
        self
    }
    /// <p>The cluster identifier (ID) for the cluster whose tags you are removing. To find the cluster ID, use <code>DescribeClusters</code>.</p>
    pub fn get_resource_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.resource_id
    }
    /// Appends an item to `tag_key_list`.
    ///
    /// To override the contents of this collection use [`set_tag_key_list`](Self::set_tag_key_list).
    ///
    /// <p>A list of one or more tag keys for the tags that you are removing. Specify only the tag keys, not the tag values.</p>
    pub fn tag_key_list(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.tag_key_list.unwrap_or_default();
        v.push(input.into());
        self.tag_key_list = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of one or more tag keys for the tags that you are removing. Specify only the tag keys, not the tag values.</p>
    pub fn set_tag_key_list(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.tag_key_list = input;
        self
    }
    /// <p>A list of one or more tag keys for the tags that you are removing. Specify only the tag keys, not the tag values.</p>
    pub fn get_tag_key_list(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.tag_key_list
    }
    /// Consumes the builder and constructs a [`UntagResourceInput`](crate::operation::untag_resource::UntagResourceInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::untag_resource::UntagResourceInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::untag_resource::UntagResourceInput {
            resource_id: self.resource_id,
            tag_key_list: self.tag_key_list,
        })
    }
}
