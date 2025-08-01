// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A partition dimension defined by a timestamp attribute.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct TimestampPartition {
    /// <p>The attribute name of the partition defined by a timestamp.</p>
    pub attribute_name: ::std::string::String,
    /// <p>The timestamp format of a partition defined by a timestamp. The default format is seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub timestamp_format: ::std::option::Option<::std::string::String>,
}
impl TimestampPartition {
    /// <p>The attribute name of the partition defined by a timestamp.</p>
    pub fn attribute_name(&self) -> &str {
        use std::ops::Deref;
        self.attribute_name.deref()
    }
    /// <p>The timestamp format of a partition defined by a timestamp. The default format is seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn timestamp_format(&self) -> ::std::option::Option<&str> {
        self.timestamp_format.as_deref()
    }
}
impl TimestampPartition {
    /// Creates a new builder-style object to manufacture [`TimestampPartition`](crate::types::TimestampPartition).
    pub fn builder() -> crate::types::builders::TimestampPartitionBuilder {
        crate::types::builders::TimestampPartitionBuilder::default()
    }
}

/// A builder for [`TimestampPartition`](crate::types::TimestampPartition).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct TimestampPartitionBuilder {
    pub(crate) attribute_name: ::std::option::Option<::std::string::String>,
    pub(crate) timestamp_format: ::std::option::Option<::std::string::String>,
}
impl TimestampPartitionBuilder {
    /// <p>The attribute name of the partition defined by a timestamp.</p>
    /// This field is required.
    pub fn attribute_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.attribute_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The attribute name of the partition defined by a timestamp.</p>
    pub fn set_attribute_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.attribute_name = input;
        self
    }
    /// <p>The attribute name of the partition defined by a timestamp.</p>
    pub fn get_attribute_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.attribute_name
    }
    /// <p>The timestamp format of a partition defined by a timestamp. The default format is seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn timestamp_format(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.timestamp_format = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The timestamp format of a partition defined by a timestamp. The default format is seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn set_timestamp_format(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.timestamp_format = input;
        self
    }
    /// <p>The timestamp format of a partition defined by a timestamp. The default format is seconds since epoch (January 1, 1970 at midnight UTC time).</p>
    pub fn get_timestamp_format(&self) -> &::std::option::Option<::std::string::String> {
        &self.timestamp_format
    }
    /// Consumes the builder and constructs a [`TimestampPartition`](crate::types::TimestampPartition).
    /// This method will fail if any of the following fields are not set:
    /// - [`attribute_name`](crate::types::builders::TimestampPartitionBuilder::attribute_name)
    pub fn build(self) -> ::std::result::Result<crate::types::TimestampPartition, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::TimestampPartition {
            attribute_name: self.attribute_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "attribute_name",
                    "attribute_name was not specified but it is required when building TimestampPartition",
                )
            })?,
            timestamp_format: self.timestamp_format,
        })
    }
}
