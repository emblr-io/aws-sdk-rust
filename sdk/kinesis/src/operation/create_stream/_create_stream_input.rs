// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input for <code>CreateStream</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateStreamInput {
    /// <p>A name to identify the stream. The stream name is scoped to the Amazon Web Services account used by the application that creates the stream. It is also scoped by Amazon Web Services Region. That is, two streams in two different Amazon Web Services accounts can have the same name. Two streams in the same Amazon Web Services account but in two different Regions can also have the same name.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The number of shards that the stream will use. The throughput of the stream is a function of the number of shards; more shards are required for greater provisioned throughput.</p>
    pub shard_count: ::std::option::Option<i32>,
    /// <p>Indicates the capacity mode of the data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub stream_mode_details: ::std::option::Option<crate::types::StreamModeDetails>,
    /// <p>A set of up to 50 key-value pairs to use to create the tags. A tag consists of a required key and an optional value.</p>
    pub tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateStreamInput {
    /// <p>A name to identify the stream. The stream name is scoped to the Amazon Web Services account used by the application that creates the stream. It is also scoped by Amazon Web Services Region. That is, two streams in two different Amazon Web Services accounts can have the same name. Two streams in the same Amazon Web Services account but in two different Regions can also have the same name.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The number of shards that the stream will use. The throughput of the stream is a function of the number of shards; more shards are required for greater provisioned throughput.</p>
    pub fn shard_count(&self) -> ::std::option::Option<i32> {
        self.shard_count
    }
    /// <p>Indicates the capacity mode of the data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn stream_mode_details(&self) -> ::std::option::Option<&crate::types::StreamModeDetails> {
        self.stream_mode_details.as_ref()
    }
    /// <p>A set of up to 50 key-value pairs to use to create the tags. A tag consists of a required key and an optional value.</p>
    pub fn tags(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.tags.as_ref()
    }
}
impl CreateStreamInput {
    /// Creates a new builder-style object to manufacture [`CreateStreamInput`](crate::operation::create_stream::CreateStreamInput).
    pub fn builder() -> crate::operation::create_stream::builders::CreateStreamInputBuilder {
        crate::operation::create_stream::builders::CreateStreamInputBuilder::default()
    }
}

/// A builder for [`CreateStreamInput`](crate::operation::create_stream::CreateStreamInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateStreamInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) shard_count: ::std::option::Option<i32>,
    pub(crate) stream_mode_details: ::std::option::Option<crate::types::StreamModeDetails>,
    pub(crate) tags: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl CreateStreamInputBuilder {
    /// <p>A name to identify the stream. The stream name is scoped to the Amazon Web Services account used by the application that creates the stream. It is also scoped by Amazon Web Services Region. That is, two streams in two different Amazon Web Services accounts can have the same name. Two streams in the same Amazon Web Services account but in two different Regions can also have the same name.</p>
    /// This field is required.
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A name to identify the stream. The stream name is scoped to the Amazon Web Services account used by the application that creates the stream. It is also scoped by Amazon Web Services Region. That is, two streams in two different Amazon Web Services accounts can have the same name. Two streams in the same Amazon Web Services account but in two different Regions can also have the same name.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>A name to identify the stream. The stream name is scoped to the Amazon Web Services account used by the application that creates the stream. It is also scoped by Amazon Web Services Region. That is, two streams in two different Amazon Web Services accounts can have the same name. Two streams in the same Amazon Web Services account but in two different Regions can also have the same name.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The number of shards that the stream will use. The throughput of the stream is a function of the number of shards; more shards are required for greater provisioned throughput.</p>
    pub fn shard_count(mut self, input: i32) -> Self {
        self.shard_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of shards that the stream will use. The throughput of the stream is a function of the number of shards; more shards are required for greater provisioned throughput.</p>
    pub fn set_shard_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.shard_count = input;
        self
    }
    /// <p>The number of shards that the stream will use. The throughput of the stream is a function of the number of shards; more shards are required for greater provisioned throughput.</p>
    pub fn get_shard_count(&self) -> &::std::option::Option<i32> {
        &self.shard_count
    }
    /// <p>Indicates the capacity mode of the data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn stream_mode_details(mut self, input: crate::types::StreamModeDetails) -> Self {
        self.stream_mode_details = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the capacity mode of the data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn set_stream_mode_details(mut self, input: ::std::option::Option<crate::types::StreamModeDetails>) -> Self {
        self.stream_mode_details = input;
        self
    }
    /// <p>Indicates the capacity mode of the data stream. Currently, in Kinesis Data Streams, you can choose between an <b>on-demand</b> capacity mode and a <b>provisioned</b> capacity mode for your data streams.</p>
    pub fn get_stream_mode_details(&self) -> &::std::option::Option<crate::types::StreamModeDetails> {
        &self.stream_mode_details
    }
    /// Adds a key-value pair to `tags`.
    ///
    /// To override the contents of this collection use [`set_tags`](Self::set_tags).
    ///
    /// <p>A set of up to 50 key-value pairs to use to create the tags. A tag consists of a required key and an optional value.</p>
    pub fn tags(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.tags.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.tags = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A set of up to 50 key-value pairs to use to create the tags. A tag consists of a required key and an optional value.</p>
    pub fn set_tags(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.tags = input;
        self
    }
    /// <p>A set of up to 50 key-value pairs to use to create the tags. A tag consists of a required key and an optional value.</p>
    pub fn get_tags(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.tags
    }
    /// Consumes the builder and constructs a [`CreateStreamInput`](crate::operation::create_stream::CreateStreamInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::create_stream::CreateStreamInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::create_stream::CreateStreamInput {
            stream_name: self.stream_name,
            shard_count: self.shard_count,
            stream_mode_details: self.stream_mode_details,
            tags: self.tags,
        })
    }
}
