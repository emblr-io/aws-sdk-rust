// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Defines a complete set of updates to be applied to an Iceberg table, including schema changes, partitioning modifications, sort order adjustments, location updates, and property changes.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct IcebergTableUpdate {
    /// <p>The updated schema definition for the Iceberg table, specifying any changes to field structure, data types, or schema metadata.</p>
    pub schema: ::std::option::Option<crate::types::IcebergSchema>,
    /// <p>The updated partitioning specification that defines how the table data should be reorganized and partitioned.</p>
    pub partition_spec: ::std::option::Option<crate::types::IcebergPartitionSpec>,
    /// <p>The updated sort order specification that defines how data should be ordered within partitions for optimal query performance.</p>
    pub sort_order: ::std::option::Option<crate::types::IcebergSortOrder>,
    /// <p>The updated S3 location where the Iceberg table data will be stored.</p>
    pub location: ::std::string::String,
    /// <p>Updated key-value pairs of table properties and configuration settings for the Iceberg table.</p>
    pub properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl IcebergTableUpdate {
    /// <p>The updated schema definition for the Iceberg table, specifying any changes to field structure, data types, or schema metadata.</p>
    pub fn schema(&self) -> ::std::option::Option<&crate::types::IcebergSchema> {
        self.schema.as_ref()
    }
    /// <p>The updated partitioning specification that defines how the table data should be reorganized and partitioned.</p>
    pub fn partition_spec(&self) -> ::std::option::Option<&crate::types::IcebergPartitionSpec> {
        self.partition_spec.as_ref()
    }
    /// <p>The updated sort order specification that defines how data should be ordered within partitions for optimal query performance.</p>
    pub fn sort_order(&self) -> ::std::option::Option<&crate::types::IcebergSortOrder> {
        self.sort_order.as_ref()
    }
    /// <p>The updated S3 location where the Iceberg table data will be stored.</p>
    pub fn location(&self) -> &str {
        use std::ops::Deref;
        self.location.deref()
    }
    /// <p>Updated key-value pairs of table properties and configuration settings for the Iceberg table.</p>
    pub fn properties(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        self.properties.as_ref()
    }
}
impl IcebergTableUpdate {
    /// Creates a new builder-style object to manufacture [`IcebergTableUpdate`](crate::types::IcebergTableUpdate).
    pub fn builder() -> crate::types::builders::IcebergTableUpdateBuilder {
        crate::types::builders::IcebergTableUpdateBuilder::default()
    }
}

/// A builder for [`IcebergTableUpdate`](crate::types::IcebergTableUpdate).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct IcebergTableUpdateBuilder {
    pub(crate) schema: ::std::option::Option<crate::types::IcebergSchema>,
    pub(crate) partition_spec: ::std::option::Option<crate::types::IcebergPartitionSpec>,
    pub(crate) sort_order: ::std::option::Option<crate::types::IcebergSortOrder>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
    pub(crate) properties: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>,
}
impl IcebergTableUpdateBuilder {
    /// <p>The updated schema definition for the Iceberg table, specifying any changes to field structure, data types, or schema metadata.</p>
    /// This field is required.
    pub fn schema(mut self, input: crate::types::IcebergSchema) -> Self {
        self.schema = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated schema definition for the Iceberg table, specifying any changes to field structure, data types, or schema metadata.</p>
    pub fn set_schema(mut self, input: ::std::option::Option<crate::types::IcebergSchema>) -> Self {
        self.schema = input;
        self
    }
    /// <p>The updated schema definition for the Iceberg table, specifying any changes to field structure, data types, or schema metadata.</p>
    pub fn get_schema(&self) -> &::std::option::Option<crate::types::IcebergSchema> {
        &self.schema
    }
    /// <p>The updated partitioning specification that defines how the table data should be reorganized and partitioned.</p>
    pub fn partition_spec(mut self, input: crate::types::IcebergPartitionSpec) -> Self {
        self.partition_spec = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated partitioning specification that defines how the table data should be reorganized and partitioned.</p>
    pub fn set_partition_spec(mut self, input: ::std::option::Option<crate::types::IcebergPartitionSpec>) -> Self {
        self.partition_spec = input;
        self
    }
    /// <p>The updated partitioning specification that defines how the table data should be reorganized and partitioned.</p>
    pub fn get_partition_spec(&self) -> &::std::option::Option<crate::types::IcebergPartitionSpec> {
        &self.partition_spec
    }
    /// <p>The updated sort order specification that defines how data should be ordered within partitions for optimal query performance.</p>
    pub fn sort_order(mut self, input: crate::types::IcebergSortOrder) -> Self {
        self.sort_order = ::std::option::Option::Some(input);
        self
    }
    /// <p>The updated sort order specification that defines how data should be ordered within partitions for optimal query performance.</p>
    pub fn set_sort_order(mut self, input: ::std::option::Option<crate::types::IcebergSortOrder>) -> Self {
        self.sort_order = input;
        self
    }
    /// <p>The updated sort order specification that defines how data should be ordered within partitions for optimal query performance.</p>
    pub fn get_sort_order(&self) -> &::std::option::Option<crate::types::IcebergSortOrder> {
        &self.sort_order
    }
    /// <p>The updated S3 location where the Iceberg table data will be stored.</p>
    /// This field is required.
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The updated S3 location where the Iceberg table data will be stored.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The updated S3 location where the Iceberg table data will be stored.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// Adds a key-value pair to `properties`.
    ///
    /// To override the contents of this collection use [`set_properties`](Self::set_properties).
    ///
    /// <p>Updated key-value pairs of table properties and configuration settings for the Iceberg table.</p>
    pub fn properties(mut self, k: impl ::std::convert::Into<::std::string::String>, v: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut hash_map = self.properties.unwrap_or_default();
        hash_map.insert(k.into(), v.into());
        self.properties = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>Updated key-value pairs of table properties and configuration settings for the Iceberg table.</p>
    pub fn set_properties(mut self, input: ::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>>) -> Self {
        self.properties = input;
        self
    }
    /// <p>Updated key-value pairs of table properties and configuration settings for the Iceberg table.</p>
    pub fn get_properties(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, ::std::string::String>> {
        &self.properties
    }
    /// Consumes the builder and constructs a [`IcebergTableUpdate`](crate::types::IcebergTableUpdate).
    /// This method will fail if any of the following fields are not set:
    /// - [`location`](crate::types::builders::IcebergTableUpdateBuilder::location)
    pub fn build(self) -> ::std::result::Result<crate::types::IcebergTableUpdate, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::IcebergTableUpdate {
            schema: self.schema,
            partition_spec: self.partition_spec,
            sort_order: self.sort_order,
            location: self.location.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "location",
                    "location was not specified but it is required when building IcebergTableUpdate",
                )
            })?,
            properties: self.properties,
        })
    }
}
