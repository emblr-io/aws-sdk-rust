// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a request to perform a <code>PutItem</code> operation on an item.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PutRequest {
    /// <p>A map of attribute name to attribute values, representing the primary key of an item to be processed by <code>PutItem</code>. All of the table's primary key attributes must be specified, and their data types must match those of the table's key schema. If any attributes are present in the item that are part of an index key schema for the table, their types must match the index key schema.</p>
    pub item: ::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>,
}
impl PutRequest {
    /// <p>A map of attribute name to attribute values, representing the primary key of an item to be processed by <code>PutItem</code>. All of the table's primary key attributes must be specified, and their data types must match those of the table's key schema. If any attributes are present in the item that are part of an index key schema for the table, their types must match the index key schema.</p>
    pub fn item(&self) -> &::std::collections::HashMap<::std::string::String, crate::types::AttributeValue> {
        &self.item
    }
}
impl PutRequest {
    /// Creates a new builder-style object to manufacture [`PutRequest`](crate::types::PutRequest).
    pub fn builder() -> crate::types::builders::PutRequestBuilder {
        crate::types::builders::PutRequestBuilder::default()
    }
}

/// A builder for [`PutRequest`](crate::types::PutRequest).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PutRequestBuilder {
    pub(crate) item: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
}
impl PutRequestBuilder {
    /// Adds a key-value pair to `item`.
    ///
    /// To override the contents of this collection use [`set_item`](Self::set_item).
    ///
    /// <p>A map of attribute name to attribute values, representing the primary key of an item to be processed by <code>PutItem</code>. All of the table's primary key attributes must be specified, and their data types must match those of the table's key schema. If any attributes are present in the item that are part of an index key schema for the table, their types must match the index key schema.</p>
    pub fn item(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::AttributeValue) -> Self {
        let mut hash_map = self.item.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.item = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of attribute name to attribute values, representing the primary key of an item to be processed by <code>PutItem</code>. All of the table's primary key attributes must be specified, and their data types must match those of the table's key schema. If any attributes are present in the item that are part of an index key schema for the table, their types must match the index key schema.</p>
    pub fn set_item(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    ) -> Self {
        self.item = input;
        self
    }
    /// <p>A map of attribute name to attribute values, representing the primary key of an item to be processed by <code>PutItem</code>. All of the table's primary key attributes must be specified, and their data types must match those of the table's key schema. If any attributes are present in the item that are part of an index key schema for the table, their types must match the index key schema.</p>
    pub fn get_item(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>> {
        &self.item
    }
    /// Consumes the builder and constructs a [`PutRequest`](crate::types::PutRequest).
    /// This method will fail if any of the following fields are not set:
    /// - [`item`](crate::types::builders::PutRequestBuilder::item)
    pub fn build(self) -> ::std::result::Result<crate::types::PutRequest, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::PutRequest {
            item: self.item.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "item",
                    "item was not specified but it is required when building PutRequest",
                )
            })?,
        })
    }
}
