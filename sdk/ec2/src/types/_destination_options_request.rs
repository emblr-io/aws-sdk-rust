// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Describes the destination options for a flow log.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DestinationOptionsRequest {
    /// <p>The format for the flow log. The default is <code>plain-text</code>.</p>
    pub file_format: ::std::option::Option<crate::types::DestinationFileFormat>,
    /// <p>Indicates whether to use Hive-compatible prefixes for flow logs stored in Amazon S3. The default is <code>false</code>.</p>
    pub hive_compatible_partitions: ::std::option::Option<bool>,
    /// <p>Indicates whether to partition the flow log per hour. This reduces the cost and response time for queries. The default is <code>false</code>.</p>
    pub per_hour_partition: ::std::option::Option<bool>,
}
impl DestinationOptionsRequest {
    /// <p>The format for the flow log. The default is <code>plain-text</code>.</p>
    pub fn file_format(&self) -> ::std::option::Option<&crate::types::DestinationFileFormat> {
        self.file_format.as_ref()
    }
    /// <p>Indicates whether to use Hive-compatible prefixes for flow logs stored in Amazon S3. The default is <code>false</code>.</p>
    pub fn hive_compatible_partitions(&self) -> ::std::option::Option<bool> {
        self.hive_compatible_partitions
    }
    /// <p>Indicates whether to partition the flow log per hour. This reduces the cost and response time for queries. The default is <code>false</code>.</p>
    pub fn per_hour_partition(&self) -> ::std::option::Option<bool> {
        self.per_hour_partition
    }
}
impl DestinationOptionsRequest {
    /// Creates a new builder-style object to manufacture [`DestinationOptionsRequest`](crate::types::DestinationOptionsRequest).
    pub fn builder() -> crate::types::builders::DestinationOptionsRequestBuilder {
        crate::types::builders::DestinationOptionsRequestBuilder::default()
    }
}

/// A builder for [`DestinationOptionsRequest`](crate::types::DestinationOptionsRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DestinationOptionsRequestBuilder {
    pub(crate) file_format: ::std::option::Option<crate::types::DestinationFileFormat>,
    pub(crate) hive_compatible_partitions: ::std::option::Option<bool>,
    pub(crate) per_hour_partition: ::std::option::Option<bool>,
}
impl DestinationOptionsRequestBuilder {
    /// <p>The format for the flow log. The default is <code>plain-text</code>.</p>
    pub fn file_format(mut self, input: crate::types::DestinationFileFormat) -> Self {
        self.file_format = ::std::option::Option::Some(input);
        self
    }
    /// <p>The format for the flow log. The default is <code>plain-text</code>.</p>
    pub fn set_file_format(mut self, input: ::std::option::Option<crate::types::DestinationFileFormat>) -> Self {
        self.file_format = input;
        self
    }
    /// <p>The format for the flow log. The default is <code>plain-text</code>.</p>
    pub fn get_file_format(&self) -> &::std::option::Option<crate::types::DestinationFileFormat> {
        &self.file_format
    }
    /// <p>Indicates whether to use Hive-compatible prefixes for flow logs stored in Amazon S3. The default is <code>false</code>.</p>
    pub fn hive_compatible_partitions(mut self, input: bool) -> Self {
        self.hive_compatible_partitions = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to use Hive-compatible prefixes for flow logs stored in Amazon S3. The default is <code>false</code>.</p>
    pub fn set_hive_compatible_partitions(mut self, input: ::std::option::Option<bool>) -> Self {
        self.hive_compatible_partitions = input;
        self
    }
    /// <p>Indicates whether to use Hive-compatible prefixes for flow logs stored in Amazon S3. The default is <code>false</code>.</p>
    pub fn get_hive_compatible_partitions(&self) -> &::std::option::Option<bool> {
        &self.hive_compatible_partitions
    }
    /// <p>Indicates whether to partition the flow log per hour. This reduces the cost and response time for queries. The default is <code>false</code>.</p>
    pub fn per_hour_partition(mut self, input: bool) -> Self {
        self.per_hour_partition = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates whether to partition the flow log per hour. This reduces the cost and response time for queries. The default is <code>false</code>.</p>
    pub fn set_per_hour_partition(mut self, input: ::std::option::Option<bool>) -> Self {
        self.per_hour_partition = input;
        self
    }
    /// <p>Indicates whether to partition the flow log per hour. This reduces the cost and response time for queries. The default is <code>false</code>.</p>
    pub fn get_per_hour_partition(&self) -> &::std::option::Option<bool> {
        &self.per_hour_partition
    }
    /// Consumes the builder and constructs a [`DestinationOptionsRequest`](crate::types::DestinationOptionsRequest).
    pub fn build(self) -> crate::types::DestinationOptionsRequest {
        crate::types::DestinationOptionsRequest {
            file_format: self.file_format,
            hive_compatible_partitions: self.hive_compatible_partitions,
            per_hour_partition: self.per_hour_partition,
        }
    }
}
