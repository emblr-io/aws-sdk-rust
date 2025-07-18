// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A Schema specifies the expected data model of the table.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct Schema {
    /// <p>A non-empty list of partition keys defining the attributes used to partition the table data. The order of the list determines the partition hierarchy. The name and type of each partition key as well as the partition key order cannot be changed after the table is created. However, the enforcement level of each partition key can be changed.</p>
    pub composite_partition_key: ::std::option::Option<::std::vec::Vec<crate::types::PartitionKey>>,
}
impl Schema {
    /// <p>A non-empty list of partition keys defining the attributes used to partition the table data. The order of the list determines the partition hierarchy. The name and type of each partition key as well as the partition key order cannot be changed after the table is created. However, the enforcement level of each partition key can be changed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.composite_partition_key.is_none()`.
    pub fn composite_partition_key(&self) -> &[crate::types::PartitionKey] {
        self.composite_partition_key.as_deref().unwrap_or_default()
    }
}
impl Schema {
    /// Creates a new builder-style object to manufacture [`Schema`](crate::types::Schema).
    pub fn builder() -> crate::types::builders::SchemaBuilder {
        crate::types::builders::SchemaBuilder::default()
    }
}

/// A builder for [`Schema`](crate::types::Schema).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SchemaBuilder {
    pub(crate) composite_partition_key: ::std::option::Option<::std::vec::Vec<crate::types::PartitionKey>>,
}
impl SchemaBuilder {
    /// Appends an item to `composite_partition_key`.
    ///
    /// To override the contents of this collection use [`set_composite_partition_key`](Self::set_composite_partition_key).
    ///
    /// <p>A non-empty list of partition keys defining the attributes used to partition the table data. The order of the list determines the partition hierarchy. The name and type of each partition key as well as the partition key order cannot be changed after the table is created. However, the enforcement level of each partition key can be changed.</p>
    pub fn composite_partition_key(mut self, input: crate::types::PartitionKey) -> Self {
        let mut v = self.composite_partition_key.unwrap_or_default();
        v.push(input);
        self.composite_partition_key = ::std::option::Option::Some(v);
        self
    }
    /// <p>A non-empty list of partition keys defining the attributes used to partition the table data. The order of the list determines the partition hierarchy. The name and type of each partition key as well as the partition key order cannot be changed after the table is created. However, the enforcement level of each partition key can be changed.</p>
    pub fn set_composite_partition_key(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::PartitionKey>>) -> Self {
        self.composite_partition_key = input;
        self
    }
    /// <p>A non-empty list of partition keys defining the attributes used to partition the table data. The order of the list determines the partition hierarchy. The name and type of each partition key as well as the partition key order cannot be changed after the table is created. However, the enforcement level of each partition key can be changed.</p>
    pub fn get_composite_partition_key(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::PartitionKey>> {
        &self.composite_partition_key
    }
    /// Consumes the builder and constructs a [`Schema`](crate::types::Schema).
    pub fn build(self) -> crate::types::Schema {
        crate::types::Schema {
            composite_partition_key: self.composite_partition_key,
        }
    }
}
