// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of an <code>UpdateItem</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateItemOutput {
    /// <p>A map of attribute values as they appear before or after the <code>UpdateItem</code> operation, as determined by the <code>ReturnValues</code> parameter.</p>
    /// <p>The <code>Attributes</code> map is only present if the update was successful and <code>ReturnValues</code> was specified as something other than <code>NONE</code> in the request. Each element represents one attribute.</p>
    pub attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    /// <p>The capacity units consumed by the <code>UpdateItem</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#write-operation-consumption">Capacity unity consumption for write operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub consumed_capacity: ::std::option::Option<crate::types::ConsumedCapacity>,
    /// <p>Information about item collections, if any, that were affected by the <code>UpdateItem</code> operation. <code>ItemCollectionMetrics</code> is only returned if the <code>ReturnItemCollectionMetrics</code> parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response.</p>
    /// <p>Each <code>ItemCollectionMetrics</code> element consists of:</p>
    /// <ul>
    /// <li>
    /// <p><code>ItemCollectionKey</code> - The partition key value of the item collection. This is the same as the partition key value of the item itself.</p></li>
    /// <li>
    /// <p><code>SizeEstimateRangeGB</code> - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit.</p>
    /// <p>The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate.</p></li>
    /// </ul>
    pub item_collection_metrics: ::std::option::Option<crate::types::ItemCollectionMetrics>,
    _request_id: Option<String>,
}
impl UpdateItemOutput {
    /// <p>A map of attribute values as they appear before or after the <code>UpdateItem</code> operation, as determined by the <code>ReturnValues</code> parameter.</p>
    /// <p>The <code>Attributes</code> map is only present if the update was successful and <code>ReturnValues</code> was specified as something other than <code>NONE</code> in the request. Each element represents one attribute.</p>
    pub fn attributes(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>> {
        self.attributes.as_ref()
    }
    /// <p>The capacity units consumed by the <code>UpdateItem</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#write-operation-consumption">Capacity unity consumption for write operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn consumed_capacity(&self) -> ::std::option::Option<&crate::types::ConsumedCapacity> {
        self.consumed_capacity.as_ref()
    }
    /// <p>Information about item collections, if any, that were affected by the <code>UpdateItem</code> operation. <code>ItemCollectionMetrics</code> is only returned if the <code>ReturnItemCollectionMetrics</code> parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response.</p>
    /// <p>Each <code>ItemCollectionMetrics</code> element consists of:</p>
    /// <ul>
    /// <li>
    /// <p><code>ItemCollectionKey</code> - The partition key value of the item collection. This is the same as the partition key value of the item itself.</p></li>
    /// <li>
    /// <p><code>SizeEstimateRangeGB</code> - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit.</p>
    /// <p>The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate.</p></li>
    /// </ul>
    pub fn item_collection_metrics(&self) -> ::std::option::Option<&crate::types::ItemCollectionMetrics> {
        self.item_collection_metrics.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for UpdateItemOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl UpdateItemOutput {
    /// Creates a new builder-style object to manufacture [`UpdateItemOutput`](crate::operation::update_item::UpdateItemOutput).
    pub fn builder() -> crate::operation::update_item::builders::UpdateItemOutputBuilder {
        crate::operation::update_item::builders::UpdateItemOutputBuilder::default()
    }
}

/// A builder for [`UpdateItemOutput`](crate::operation::update_item::UpdateItemOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateItemOutputBuilder {
    pub(crate) attributes: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    pub(crate) consumed_capacity: ::std::option::Option<crate::types::ConsumedCapacity>,
    pub(crate) item_collection_metrics: ::std::option::Option<crate::types::ItemCollectionMetrics>,
    _request_id: Option<String>,
}
impl UpdateItemOutputBuilder {
    /// Adds a key-value pair to `attributes`.
    ///
    /// To override the contents of this collection use [`set_attributes`](Self::set_attributes).
    ///
    /// <p>A map of attribute values as they appear before or after the <code>UpdateItem</code> operation, as determined by the <code>ReturnValues</code> parameter.</p>
    /// <p>The <code>Attributes</code> map is only present if the update was successful and <code>ReturnValues</code> was specified as something other than <code>NONE</code> in the request. Each element represents one attribute.</p>
    pub fn attributes(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::AttributeValue) -> Self {
        let mut hash_map = self.attributes.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.attributes = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>A map of attribute values as they appear before or after the <code>UpdateItem</code> operation, as determined by the <code>ReturnValues</code> parameter.</p>
    /// <p>The <code>Attributes</code> map is only present if the update was successful and <code>ReturnValues</code> was specified as something other than <code>NONE</code> in the request. Each element represents one attribute.</p>
    pub fn set_attributes(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    ) -> Self {
        self.attributes = input;
        self
    }
    /// <p>A map of attribute values as they appear before or after the <code>UpdateItem</code> operation, as determined by the <code>ReturnValues</code> parameter.</p>
    /// <p>The <code>Attributes</code> map is only present if the update was successful and <code>ReturnValues</code> was specified as something other than <code>NONE</code> in the request. Each element represents one attribute.</p>
    pub fn get_attributes(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>> {
        &self.attributes
    }
    /// <p>The capacity units consumed by the <code>UpdateItem</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#write-operation-consumption">Capacity unity consumption for write operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn consumed_capacity(mut self, input: crate::types::ConsumedCapacity) -> Self {
        self.consumed_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The capacity units consumed by the <code>UpdateItem</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#write-operation-consumption">Capacity unity consumption for write operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn set_consumed_capacity(mut self, input: ::std::option::Option<crate::types::ConsumedCapacity>) -> Self {
        self.consumed_capacity = input;
        self
    }
    /// <p>The capacity units consumed by the <code>UpdateItem</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#write-operation-consumption">Capacity unity consumption for write operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn get_consumed_capacity(&self) -> &::std::option::Option<crate::types::ConsumedCapacity> {
        &self.consumed_capacity
    }
    /// <p>Information about item collections, if any, that were affected by the <code>UpdateItem</code> operation. <code>ItemCollectionMetrics</code> is only returned if the <code>ReturnItemCollectionMetrics</code> parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response.</p>
    /// <p>Each <code>ItemCollectionMetrics</code> element consists of:</p>
    /// <ul>
    /// <li>
    /// <p><code>ItemCollectionKey</code> - The partition key value of the item collection. This is the same as the partition key value of the item itself.</p></li>
    /// <li>
    /// <p><code>SizeEstimateRangeGB</code> - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit.</p>
    /// <p>The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate.</p></li>
    /// </ul>
    pub fn item_collection_metrics(mut self, input: crate::types::ItemCollectionMetrics) -> Self {
        self.item_collection_metrics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about item collections, if any, that were affected by the <code>UpdateItem</code> operation. <code>ItemCollectionMetrics</code> is only returned if the <code>ReturnItemCollectionMetrics</code> parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response.</p>
    /// <p>Each <code>ItemCollectionMetrics</code> element consists of:</p>
    /// <ul>
    /// <li>
    /// <p><code>ItemCollectionKey</code> - The partition key value of the item collection. This is the same as the partition key value of the item itself.</p></li>
    /// <li>
    /// <p><code>SizeEstimateRangeGB</code> - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit.</p>
    /// <p>The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate.</p></li>
    /// </ul>
    pub fn set_item_collection_metrics(mut self, input: ::std::option::Option<crate::types::ItemCollectionMetrics>) -> Self {
        self.item_collection_metrics = input;
        self
    }
    /// <p>Information about item collections, if any, that were affected by the <code>UpdateItem</code> operation. <code>ItemCollectionMetrics</code> is only returned if the <code>ReturnItemCollectionMetrics</code> parameter was specified. If the table does not have any local secondary indexes, this information is not returned in the response.</p>
    /// <p>Each <code>ItemCollectionMetrics</code> element consists of:</p>
    /// <ul>
    /// <li>
    /// <p><code>ItemCollectionKey</code> - The partition key value of the item collection. This is the same as the partition key value of the item itself.</p></li>
    /// <li>
    /// <p><code>SizeEstimateRangeGB</code> - An estimate of item collection size, in gigabytes. This value is a two-element array containing a lower bound and an upper bound for the estimate. The estimate includes the size of all the items in the table, plus the size of all attributes projected into all of the local secondary indexes on that table. Use this estimate to measure whether a local secondary index is approaching its size limit.</p>
    /// <p>The estimate is subject to change over time; therefore, do not rely on the precision or accuracy of the estimate.</p></li>
    /// </ul>
    pub fn get_item_collection_metrics(&self) -> &::std::option::Option<crate::types::ItemCollectionMetrics> {
        &self.item_collection_metrics
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`UpdateItemOutput`](crate::operation::update_item::UpdateItemOutput).
    pub fn build(self) -> crate::operation::update_item::UpdateItemOutput {
        crate::operation::update_item::UpdateItemOutput {
            attributes: self.attributes,
            consumed_capacity: self.consumed_capacity,
            item_collection_metrics: self.item_collection_metrics,
            _request_id: self._request_id,
        }
    }
}
