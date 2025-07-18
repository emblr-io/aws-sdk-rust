// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Amazon S3 keys for log objects are partitioned in the following format:</p>
/// <p><code>\[DestinationPrefix\]\[SourceAccountId\]/\[SourceRegion\]/\[SourceBucket\]/\[YYYY\]/\[MM\]/\[DD\]/\[YYYY\]-\[MM\]-\[DD\]-\[hh\]-\[mm\]-\[ss\]-\[UniqueString\]</code></p>
/// <p>PartitionedPrefix defaults to EventTime delivery when server access logs are delivered.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PartitionedPrefix {
    /// <p>Specifies the partition date source for the partitioned prefix. <code>PartitionDateSource</code> can be <code>EventTime</code> or <code>DeliveryTime</code>.</p>
    /// <p>For <code>DeliveryTime</code>, the time in the log file names corresponds to the delivery time for the log files.</p>
    /// <p>For <code>EventTime</code>, The logs delivered are for a specific day only. The year, month, and day correspond to the day on which the event occurred, and the hour, minutes and seconds are set to 00 in the key.</p>
    pub partition_date_source: ::std::option::Option<crate::types::PartitionDateSource>,
}
impl PartitionedPrefix {
    /// <p>Specifies the partition date source for the partitioned prefix. <code>PartitionDateSource</code> can be <code>EventTime</code> or <code>DeliveryTime</code>.</p>
    /// <p>For <code>DeliveryTime</code>, the time in the log file names corresponds to the delivery time for the log files.</p>
    /// <p>For <code>EventTime</code>, The logs delivered are for a specific day only. The year, month, and day correspond to the day on which the event occurred, and the hour, minutes and seconds are set to 00 in the key.</p>
    pub fn partition_date_source(&self) -> ::std::option::Option<&crate::types::PartitionDateSource> {
        self.partition_date_source.as_ref()
    }
}
impl PartitionedPrefix {
    /// Creates a new builder-style object to manufacture [`PartitionedPrefix`](crate::types::PartitionedPrefix).
    pub fn builder() -> crate::types::builders::PartitionedPrefixBuilder {
        crate::types::builders::PartitionedPrefixBuilder::default()
    }
}

/// A builder for [`PartitionedPrefix`](crate::types::PartitionedPrefix).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PartitionedPrefixBuilder {
    pub(crate) partition_date_source: ::std::option::Option<crate::types::PartitionDateSource>,
}
impl PartitionedPrefixBuilder {
    /// <p>Specifies the partition date source for the partitioned prefix. <code>PartitionDateSource</code> can be <code>EventTime</code> or <code>DeliveryTime</code>.</p>
    /// <p>For <code>DeliveryTime</code>, the time in the log file names corresponds to the delivery time for the log files.</p>
    /// <p>For <code>EventTime</code>, The logs delivered are for a specific day only. The year, month, and day correspond to the day on which the event occurred, and the hour, minutes and seconds are set to 00 in the key.</p>
    pub fn partition_date_source(mut self, input: crate::types::PartitionDateSource) -> Self {
        self.partition_date_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the partition date source for the partitioned prefix. <code>PartitionDateSource</code> can be <code>EventTime</code> or <code>DeliveryTime</code>.</p>
    /// <p>For <code>DeliveryTime</code>, the time in the log file names corresponds to the delivery time for the log files.</p>
    /// <p>For <code>EventTime</code>, The logs delivered are for a specific day only. The year, month, and day correspond to the day on which the event occurred, and the hour, minutes and seconds are set to 00 in the key.</p>
    pub fn set_partition_date_source(mut self, input: ::std::option::Option<crate::types::PartitionDateSource>) -> Self {
        self.partition_date_source = input;
        self
    }
    /// <p>Specifies the partition date source for the partitioned prefix. <code>PartitionDateSource</code> can be <code>EventTime</code> or <code>DeliveryTime</code>.</p>
    /// <p>For <code>DeliveryTime</code>, the time in the log file names corresponds to the delivery time for the log files.</p>
    /// <p>For <code>EventTime</code>, The logs delivered are for a specific day only. The year, month, and day correspond to the day on which the event occurred, and the hour, minutes and seconds are set to 00 in the key.</p>
    pub fn get_partition_date_source(&self) -> &::std::option::Option<crate::types::PartitionDateSource> {
        &self.partition_date_source
    }
    /// Consumes the builder and constructs a [`PartitionedPrefix`](crate::types::PartitionedPrefix).
    pub fn build(self) -> crate::types::PartitionedPrefix {
        crate::types::PartitionedPrefix {
            partition_date_source: self.partition_date_source,
        }
    }
}
