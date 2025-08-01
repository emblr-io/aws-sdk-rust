// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListTagsForDeliveryStreamInput {
    /// <p>The name of the Firehose stream whose tags you want to list.</p>
    pub delivery_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The key to use as the starting point for the list of tags. If you set this parameter, <code>ListTagsForDeliveryStream</code> gets all tags that occur after <code>ExclusiveStartTagKey</code>.</p>
    pub exclusive_start_tag_key: ::std::option::Option<::std::string::String>,
    /// <p>The number of tags to return. If this number is less than the total number of tags associated with the Firehose stream, <code>HasMoreTags</code> is set to <code>true</code> in the response. To list additional tags, set <code>ExclusiveStartTagKey</code> to the last key in the response.</p>
    pub limit: ::std::option::Option<i32>,
}
impl ListTagsForDeliveryStreamInput {
    /// <p>The name of the Firehose stream whose tags you want to list.</p>
    pub fn delivery_stream_name(&self) -> ::std::option::Option<&str> {
        self.delivery_stream_name.as_deref()
    }
    /// <p>The key to use as the starting point for the list of tags. If you set this parameter, <code>ListTagsForDeliveryStream</code> gets all tags that occur after <code>ExclusiveStartTagKey</code>.</p>
    pub fn exclusive_start_tag_key(&self) -> ::std::option::Option<&str> {
        self.exclusive_start_tag_key.as_deref()
    }
    /// <p>The number of tags to return. If this number is less than the total number of tags associated with the Firehose stream, <code>HasMoreTags</code> is set to <code>true</code> in the response. To list additional tags, set <code>ExclusiveStartTagKey</code> to the last key in the response.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
}
impl ListTagsForDeliveryStreamInput {
    /// Creates a new builder-style object to manufacture [`ListTagsForDeliveryStreamInput`](crate::operation::list_tags_for_delivery_stream::ListTagsForDeliveryStreamInput).
    pub fn builder() -> crate::operation::list_tags_for_delivery_stream::builders::ListTagsForDeliveryStreamInputBuilder {
        crate::operation::list_tags_for_delivery_stream::builders::ListTagsForDeliveryStreamInputBuilder::default()
    }
}

/// A builder for [`ListTagsForDeliveryStreamInput`](crate::operation::list_tags_for_delivery_stream::ListTagsForDeliveryStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListTagsForDeliveryStreamInputBuilder {
    pub(crate) delivery_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) exclusive_start_tag_key: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
}
impl ListTagsForDeliveryStreamInputBuilder {
    /// <p>The name of the Firehose stream whose tags you want to list.</p>
    /// This field is required.
    pub fn delivery_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Firehose stream whose tags you want to list.</p>
    pub fn set_delivery_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_stream_name = input;
        self
    }
    /// <p>The name of the Firehose stream whose tags you want to list.</p>
    pub fn get_delivery_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_stream_name
    }
    /// <p>The key to use as the starting point for the list of tags. If you set this parameter, <code>ListTagsForDeliveryStream</code> gets all tags that occur after <code>ExclusiveStartTagKey</code>.</p>
    pub fn exclusive_start_tag_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.exclusive_start_tag_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The key to use as the starting point for the list of tags. If you set this parameter, <code>ListTagsForDeliveryStream</code> gets all tags that occur after <code>ExclusiveStartTagKey</code>.</p>
    pub fn set_exclusive_start_tag_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.exclusive_start_tag_key = input;
        self
    }
    /// <p>The key to use as the starting point for the list of tags. If you set this parameter, <code>ListTagsForDeliveryStream</code> gets all tags that occur after <code>ExclusiveStartTagKey</code>.</p>
    pub fn get_exclusive_start_tag_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.exclusive_start_tag_key
    }
    /// <p>The number of tags to return. If this number is less than the total number of tags associated with the Firehose stream, <code>HasMoreTags</code> is set to <code>true</code> in the response. To list additional tags, set <code>ExclusiveStartTagKey</code> to the last key in the response.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of tags to return. If this number is less than the total number of tags associated with the Firehose stream, <code>HasMoreTags</code> is set to <code>true</code> in the response. To list additional tags, set <code>ExclusiveStartTagKey</code> to the last key in the response.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The number of tags to return. If this number is less than the total number of tags associated with the Firehose stream, <code>HasMoreTags</code> is set to <code>true</code> in the response. To list additional tags, set <code>ExclusiveStartTagKey</code> to the last key in the response.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Consumes the builder and constructs a [`ListTagsForDeliveryStreamInput`](crate::operation::list_tags_for_delivery_stream::ListTagsForDeliveryStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_tags_for_delivery_stream::ListTagsForDeliveryStreamInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_tags_for_delivery_stream::ListTagsForDeliveryStreamInput {
            delivery_stream_name: self.delivery_stream_name,
            exclusive_start_tag_key: self.exclusive_start_tag_key,
            limit: self.limit,
        })
    }
}
