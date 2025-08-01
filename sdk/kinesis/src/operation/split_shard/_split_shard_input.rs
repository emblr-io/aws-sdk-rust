// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the input for <code>SplitShard</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SplitShardInput {
    /// <p>The name of the stream for the shard split.</p>
    pub stream_name: ::std::option::Option<::std::string::String>,
    /// <p>The shard ID of the shard to split.</p>
    pub shard_to_split: ::std::option::Option<::std::string::String>,
    /// <p>A hash key value for the starting hash key of one of the child shards created by the split. The hash key range for a given shard constitutes a set of ordered contiguous positive integers. The value for <code>NewStartingHashKey</code> must be in the range of hash keys being mapped into the shard. The <code>NewStartingHashKey</code> hash key value and all higher hash key values in hash key range are distributed to one of the child shards. All the lower hash key values in the range are distributed to the other child shard.</p>
    pub new_starting_hash_key: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the stream.</p>
    pub stream_arn: ::std::option::Option<::std::string::String>,
}
impl SplitShardInput {
    /// <p>The name of the stream for the shard split.</p>
    pub fn stream_name(&self) -> ::std::option::Option<&str> {
        self.stream_name.as_deref()
    }
    /// <p>The shard ID of the shard to split.</p>
    pub fn shard_to_split(&self) -> ::std::option::Option<&str> {
        self.shard_to_split.as_deref()
    }
    /// <p>A hash key value for the starting hash key of one of the child shards created by the split. The hash key range for a given shard constitutes a set of ordered contiguous positive integers. The value for <code>NewStartingHashKey</code> must be in the range of hash keys being mapped into the shard. The <code>NewStartingHashKey</code> hash key value and all higher hash key values in hash key range are distributed to one of the child shards. All the lower hash key values in the range are distributed to the other child shard.</p>
    pub fn new_starting_hash_key(&self) -> ::std::option::Option<&str> {
        self.new_starting_hash_key.as_deref()
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(&self) -> ::std::option::Option<&str> {
        self.stream_arn.as_deref()
    }
}
impl SplitShardInput {
    /// Creates a new builder-style object to manufacture [`SplitShardInput`](crate::operation::split_shard::SplitShardInput).
    pub fn builder() -> crate::operation::split_shard::builders::SplitShardInputBuilder {
        crate::operation::split_shard::builders::SplitShardInputBuilder::default()
    }
}

/// A builder for [`SplitShardInput`](crate::operation::split_shard::SplitShardInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SplitShardInputBuilder {
    pub(crate) stream_name: ::std::option::Option<::std::string::String>,
    pub(crate) shard_to_split: ::std::option::Option<::std::string::String>,
    pub(crate) new_starting_hash_key: ::std::option::Option<::std::string::String>,
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
}
impl SplitShardInputBuilder {
    /// <p>The name of the stream for the shard split.</p>
    pub fn stream_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the stream for the shard split.</p>
    pub fn set_stream_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_name = input;
        self
    }
    /// <p>The name of the stream for the shard split.</p>
    pub fn get_stream_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_name
    }
    /// <p>The shard ID of the shard to split.</p>
    /// This field is required.
    pub fn shard_to_split(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.shard_to_split = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The shard ID of the shard to split.</p>
    pub fn set_shard_to_split(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.shard_to_split = input;
        self
    }
    /// <p>The shard ID of the shard to split.</p>
    pub fn get_shard_to_split(&self) -> &::std::option::Option<::std::string::String> {
        &self.shard_to_split
    }
    /// <p>A hash key value for the starting hash key of one of the child shards created by the split. The hash key range for a given shard constitutes a set of ordered contiguous positive integers. The value for <code>NewStartingHashKey</code> must be in the range of hash keys being mapped into the shard. The <code>NewStartingHashKey</code> hash key value and all higher hash key values in hash key range are distributed to one of the child shards. All the lower hash key values in the range are distributed to the other child shard.</p>
    /// This field is required.
    pub fn new_starting_hash_key(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.new_starting_hash_key = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A hash key value for the starting hash key of one of the child shards created by the split. The hash key range for a given shard constitutes a set of ordered contiguous positive integers. The value for <code>NewStartingHashKey</code> must be in the range of hash keys being mapped into the shard. The <code>NewStartingHashKey</code> hash key value and all higher hash key values in hash key range are distributed to one of the child shards. All the lower hash key values in the range are distributed to the other child shard.</p>
    pub fn set_new_starting_hash_key(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.new_starting_hash_key = input;
        self
    }
    /// <p>A hash key value for the starting hash key of one of the child shards created by the split. The hash key range for a given shard constitutes a set of ordered contiguous positive integers. The value for <code>NewStartingHashKey</code> must be in the range of hash keys being mapped into the shard. The <code>NewStartingHashKey</code> hash key value and all higher hash key values in hash key range are distributed to one of the child shards. All the lower hash key values in the range are distributed to the other child shard.</p>
    pub fn get_new_starting_hash_key(&self) -> &::std::option::Option<::std::string::String> {
        &self.new_starting_hash_key
    }
    /// <p>The ARN of the stream.</p>
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The ARN of the stream.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// Consumes the builder and constructs a [`SplitShardInput`](crate::operation::split_shard::SplitShardInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::split_shard::SplitShardInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::split_shard::SplitShardInput {
            stream_name: self.stream_name,
            shard_to_split: self.shard_to_split,
            new_starting_hash_key: self.new_starting_hash_key,
            stream_arn: self.stream_arn,
        })
    }
}
