// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a change data capture stream for an Amazon Keyspaces table, which enables tracking and processing of data changes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Stream {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies this stream.</p>
    pub stream_arn: ::std::string::String,
    /// <p>The name of the keyspace containing the table associated with this stream.</p>
    pub keyspace_name: ::std::string::String,
    /// <p>The name of the table associated with this stream.</p>
    pub table_name: ::std::string::String,
    /// <p>A unique identifier for this stream that can be used in stream operations.</p>
    pub stream_label: ::std::string::String,
}
impl Stream {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies this stream.</p>
    pub fn stream_arn(&self) -> &str {
        use std::ops::Deref;
        self.stream_arn.deref()
    }
    /// <p>The name of the keyspace containing the table associated with this stream.</p>
    pub fn keyspace_name(&self) -> &str {
        use std::ops::Deref;
        self.keyspace_name.deref()
    }
    /// <p>The name of the table associated with this stream.</p>
    pub fn table_name(&self) -> &str {
        use std::ops::Deref;
        self.table_name.deref()
    }
    /// <p>A unique identifier for this stream that can be used in stream operations.</p>
    pub fn stream_label(&self) -> &str {
        use std::ops::Deref;
        self.stream_label.deref()
    }
}
impl Stream {
    /// Creates a new builder-style object to manufacture [`Stream`](crate::types::Stream).
    pub fn builder() -> crate::types::builders::StreamBuilder {
        crate::types::builders::StreamBuilder::default()
    }
}

/// A builder for [`Stream`](crate::types::Stream).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StreamBuilder {
    pub(crate) stream_arn: ::std::option::Option<::std::string::String>,
    pub(crate) keyspace_name: ::std::option::Option<::std::string::String>,
    pub(crate) table_name: ::std::option::Option<::std::string::String>,
    pub(crate) stream_label: ::std::option::Option<::std::string::String>,
}
impl StreamBuilder {
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies this stream.</p>
    /// This field is required.
    pub fn stream_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies this stream.</p>
    pub fn set_stream_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) that uniquely identifies this stream.</p>
    pub fn get_stream_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_arn
    }
    /// <p>The name of the keyspace containing the table associated with this stream.</p>
    /// This field is required.
    pub fn keyspace_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.keyspace_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the keyspace containing the table associated with this stream.</p>
    pub fn set_keyspace_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.keyspace_name = input;
        self
    }
    /// <p>The name of the keyspace containing the table associated with this stream.</p>
    pub fn get_keyspace_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.keyspace_name
    }
    /// <p>The name of the table associated with this stream.</p>
    /// This field is required.
    pub fn table_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.table_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the table associated with this stream.</p>
    pub fn set_table_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.table_name = input;
        self
    }
    /// <p>The name of the table associated with this stream.</p>
    pub fn get_table_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.table_name
    }
    /// <p>A unique identifier for this stream that can be used in stream operations.</p>
    /// This field is required.
    pub fn stream_label(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.stream_label = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier for this stream that can be used in stream operations.</p>
    pub fn set_stream_label(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.stream_label = input;
        self
    }
    /// <p>A unique identifier for this stream that can be used in stream operations.</p>
    pub fn get_stream_label(&self) -> &::std::option::Option<::std::string::String> {
        &self.stream_label
    }
    /// Consumes the builder and constructs a [`Stream`](crate::types::Stream).
    /// This method will fail if any of the following fields are not set:
    /// - [`stream_arn`](crate::types::builders::StreamBuilder::stream_arn)
    /// - [`keyspace_name`](crate::types::builders::StreamBuilder::keyspace_name)
    /// - [`table_name`](crate::types::builders::StreamBuilder::table_name)
    /// - [`stream_label`](crate::types::builders::StreamBuilder::stream_label)
    pub fn build(self) -> ::std::result::Result<crate::types::Stream, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::Stream {
            stream_arn: self.stream_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stream_arn",
                    "stream_arn was not specified but it is required when building Stream",
                )
            })?,
            keyspace_name: self.keyspace_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "keyspace_name",
                    "keyspace_name was not specified but it is required when building Stream",
                )
            })?,
            table_name: self.table_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "table_name",
                    "table_name was not specified but it is required when building Stream",
                )
            })?,
            stream_label: self.stream_label.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "stream_label",
                    "stream_label was not specified but it is required when building Stream",
                )
            })?,
        })
    }
}
