// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDeliveryStreamInput {
    /// <p>The name of the Firehose stream.</p>
    pub delivery_stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The limit on the number of destinations to return. You can have one destination per Firehose stream.</p>
    pub limit: ::std::option::Option<i32>,
    /// <p>The ID of the destination to start returning the destination information. Firehose supports one destination per Firehose stream.</p>
    pub exclusive_start_destination_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDeliveryStreamInput {
    /// <p>The name of the Firehose stream.</p>
    pub fn delivery_stream_name(&self) -> ::std::option::Option<&str> {
        self.delivery_stream_name.as_deref()
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per Firehose stream.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
    /// <p>The ID of the destination to start returning the destination information. Firehose supports one destination per Firehose stream.</p>
    pub fn exclusive_start_destination_id(&self) -> ::std::option::Option<&str> {
        self.exclusive_start_destination_id.as_deref()
    }
}
impl DescribeDeliveryStreamInput {
    /// Creates a new builder-style object to manufacture [`DescribeDeliveryStreamInput`](crate::operation::describe_delivery_stream::DescribeDeliveryStreamInput).
    pub fn builder() -> crate::operation::describe_delivery_stream::builders::DescribeDeliveryStreamInputBuilder {
        crate::operation::describe_delivery_stream::builders::DescribeDeliveryStreamInputBuilder::default()
    }
}

/// A builder for [`DescribeDeliveryStreamInput`](crate::operation::describe_delivery_stream::DescribeDeliveryStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDeliveryStreamInputBuilder {
    pub(crate) delivery_stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
    pub(crate) exclusive_start_destination_id: ::std::option::Option<::std::string::String>,
}
impl DescribeDeliveryStreamInputBuilder {
    /// <p>The name of the Firehose stream.</p>
    /// This field is required.
    pub fn delivery_stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.delivery_stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Firehose stream.</p>
    pub fn set_delivery_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.delivery_stream_name = input;
        self
    }
    /// <p>The name of the Firehose stream.</p>
    pub fn get_delivery_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.delivery_stream_name
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per Firehose stream.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per Firehose stream.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The limit on the number of destinations to return. You can have one destination per Firehose stream.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// <p>The ID of the destination to start returning the destination information. Firehose supports one destination per Firehose stream.</p>
    pub fn exclusive_start_destination_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.exclusive_start_destination_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the destination to start returning the destination information. Firehose supports one destination per Firehose stream.</p>
    pub fn set_exclusive_start_destination_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.exclusive_start_destination_id = input;
        self
    }
    /// <p>The ID of the destination to start returning the destination information. Firehose supports one destination per Firehose stream.</p>
    pub fn get_exclusive_start_destination_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.exclusive_start_destination_id
    }
    /// Consumes the builder and constructs a [`DescribeDeliveryStreamInput`](crate::operation::describe_delivery_stream::DescribeDeliveryStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_delivery_stream::DescribeDeliveryStreamInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_delivery_stream::DescribeDeliveryStreamInput {
            delivery_stream_name: self.delivery_stream_name,
            limit: self.limit,
            exclusive_start_destination_id: self.exclusive_start_destination_id,
        })
    }
}
