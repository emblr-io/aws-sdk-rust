// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TagDeliveryStreamInput {
    /// <p>The name of the Firehose stream to which you want to add the tags.</p>
    pub delivery_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>A set of key-value pairs to use to create the tags.</p>
    pub tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagDeliveryStreamInput {
    /// <p>The name of the Firehose stream to which you want to add the tags.</p>
    pub fn delivery_stream_name(&self) -> ::std::option::Option<&str> {
        self.delivery_stream_name.as_deref()
    }
    /// <p>A set of key-value pairs to use to create the tags.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.tags.is_none()`.
    pub fn tags(&self) -> &[crate::types::Tag] {
        self.tags.as_deref().unwrap_or_default()
    }
}
impl TagDeliveryStreamInput {
    /// Creates a new builder-style object to manufacture [`TagDeliveryStreamInput`](crate::operation::tag_delivery_stream::TagDeliveryStreamInput).
    pub fn builder() -> crate::operation::tag_delivery_stream::builders::TagDeliveryStreamInputBuilder {
        crate::operation::tag_delivery_stream::builders::TagDeliveryStreamInputBuilder::default()
    }
}

/// A builder for [`TagDeliveryStreamInput`](crate::operation::tag_delivery_stream::TagDeliveryStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TagDeliveryStreamInputBuilder {
    pub(crate) delivery_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) tags: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>,
}
impl TagDeliveryStreamInputBuilder {
    /// <p>The name of the Firehose stream to which you want to add the tags.</p>
    /// This field is required.
    pub fn delivery_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Firehose stream to which you want to add the tags.</p>
    pub fn set_delivery_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_stream_name = input;
        self
    }
    /// <p>The name of the Firehose stream to which you want to add the tags.</p>
    pub fn get_delivery_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_stream_name
    }
    /// Appends an item to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A set of key-value pairs to use to create the tags.</p>
    pub fn tags(mut self, input: crate::types::Tag) -> Self {
        let mut v = self.tags.unwrap_or_default();
        v.push(input);
        self.tags = ::std::option::Option::Some(v);
        self
    }
    /// <p>A set of key-value pairs to use to create the tags.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Tag>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A set of key-value pairs to use to create the tags.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Tag>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`TagDeliveryStreamInput`](crate::operation::tag_delivery_stream::TagDeliveryStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::tag_delivery_stream::TagDeliveryStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::tag_delivery_stream::TagDeliveryStreamInput {
            delivery_stream_name: self.delivery_stream_name,
            tags: self.tags,
        })
    }
}
