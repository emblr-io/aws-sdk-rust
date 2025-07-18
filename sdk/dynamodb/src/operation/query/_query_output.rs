// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents the output of a <code>Query</code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct QueryOutput {
    /// <p>An array of item attributes that match the query criteria. Each element in this array consists of an attribute name and the value for that attribute.</p>
    pub items: ::std::option::Option<::std::vec::Vec<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>>,
    /// <p>The number of items in the response.</p>
    /// <p>If you used a <code>QueryFilter</code> in the request, then <code>Count</code> is the number of items returned after the filter was applied, and <code>ScannedCount</code> is the number of matching items before the filter was applied.</p>
    /// <p>If you did not use a filter in the request, then <code>Count</code> and <code>ScannedCount</code> are the same.</p>
    pub count: i32,
    /// <p>The number of items evaluated, before any <code>QueryFilter</code> is applied. A high <code>ScannedCount</code> value with few, or no, <code>Count</code> results indicates an inefficient <code>Query</code> operation. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Count">Count and ScannedCount</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    /// <p>If you did not use a filter in the request, then <code>ScannedCount</code> is the same as <code>Count</code>.</p>
    pub scanned_count: i32,
    /// <p>The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request.</p>
    /// <p>If <code>LastEvaluatedKey</code> is empty, then the "last page" of results has been processed and there is no more data to be retrieved.</p>
    /// <p>If <code>LastEvaluatedKey</code> is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when <code>LastEvaluatedKey</code> is empty.</p>
    pub last_evaluated_key: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    /// <p>The capacity units consumed by the <code>Query</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#read-operation-consumption">Capacity unit consumption for read operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub consumed_capacity: ::std::option::Option<crate::types::ConsumedCapacity>,
    _request_id: Option<String>,
}
impl QueryOutput {
    /// <p>An array of item attributes that match the query criteria. Each element in this array consists of an attribute name and the value for that attribute.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.items.is_none()`.
    pub fn items(&self) -> &[::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>] {
        self.items.as_deref().unwrap_or_default()
    }
    /// <p>The number of items in the response.</p>
    /// <p>If you used a <code>QueryFilter</code> in the request, then <code>Count</code> is the number of items returned after the filter was applied, and <code>ScannedCount</code> is the number of matching items before the filter was applied.</p>
    /// <p>If you did not use a filter in the request, then <code>Count</code> and <code>ScannedCount</code> are the same.</p>
    pub fn count(&self) -> i32 {
        self.count
    }
    /// <p>The number of items evaluated, before any <code>QueryFilter</code> is applied. A high <code>ScannedCount</code> value with few, or no, <code>Count</code> results indicates an inefficient <code>Query</code> operation. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Count">Count and ScannedCount</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    /// <p>If you did not use a filter in the request, then <code>ScannedCount</code> is the same as <code>Count</code>.</p>
    pub fn scanned_count(&self) -> i32 {
        self.scanned_count
    }
    /// <p>The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request.</p>
    /// <p>If <code>LastEvaluatedKey</code> is empty, then the "last page" of results has been processed and there is no more data to be retrieved.</p>
    /// <p>If <code>LastEvaluatedKey</code> is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when <code>LastEvaluatedKey</code> is empty.</p>
    pub fn last_evaluated_key(&self) -> ::std::option::Option<&::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>> {
        self.last_evaluated_key.as_ref()
    }
    /// <p>The capacity units consumed by the <code>Query</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#read-operation-consumption">Capacity unit consumption for read operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn consumed_capacity(&self) -> ::std::option::Option<&crate::types::ConsumedCapacity> {
        self.consumed_capacity.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for QueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl QueryOutput {
    /// Creates a new builder-style object to manufacture [`QueryOutput`](crate::operation::query::QueryOutput).
    pub fn builder() -> crate::operation::query::builders::QueryOutputBuilder {
        crate::operation::query::builders::QueryOutputBuilder::default()
    }
}

/// A builder for [`QueryOutput`](crate::operation::query::QueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct QueryOutputBuilder {
    pub(crate) items: ::std::option::Option<::std::vec::Vec<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>>,
    pub(crate) count: ::std::option::Option<i32>,
    pub(crate) scanned_count: ::std::option::Option<i32>,
    pub(crate) last_evaluated_key: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    pub(crate) consumed_capacity: ::std::option::Option<crate::types::ConsumedCapacity>,
    _request_id: Option<String>,
}
impl QueryOutputBuilder {
    /// Appends an item to `items`.
    ///
    /// To override the contents of this collection use [`set_items`](Self::set_items).
    ///
    /// <p>An array of item attributes that match the query criteria. Each element in this array consists of an attribute name and the value for that attribute.</p>
    pub fn items(mut self, input: ::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>) -> Self {
        let mut v = self.items.unwrap_or_default();
        v.push(input);
        self.items = ::std::option::Option::Some(v);
        self
    }
    /// <p>An array of item attributes that match the query criteria. Each element in this array consists of an attribute name and the value for that attribute.</p>
    pub fn set_items(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>>,
    ) -> Self {
        self.items = input;
        self
    }
    /// <p>An array of item attributes that match the query criteria. Each element in this array consists of an attribute name and the value for that attribute.</p>
    pub fn get_items(
        &self,
    ) -> &::std::option::Option<::std::vec::Vec<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>> {
        &self.items
    }
    /// <p>The number of items in the response.</p>
    /// <p>If you used a <code>QueryFilter</code> in the request, then <code>Count</code> is the number of items returned after the filter was applied, and <code>ScannedCount</code> is the number of matching items before the filter was applied.</p>
    /// <p>If you did not use a filter in the request, then <code>Count</code> and <code>ScannedCount</code> are the same.</p>
    pub fn count(mut self, input: i32) -> Self {
        self.count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of items in the response.</p>
    /// <p>If you used a <code>QueryFilter</code> in the request, then <code>Count</code> is the number of items returned after the filter was applied, and <code>ScannedCount</code> is the number of matching items before the filter was applied.</p>
    /// <p>If you did not use a filter in the request, then <code>Count</code> and <code>ScannedCount</code> are the same.</p>
    pub fn set_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.count = input;
        self
    }
    /// <p>The number of items in the response.</p>
    /// <p>If you used a <code>QueryFilter</code> in the request, then <code>Count</code> is the number of items returned after the filter was applied, and <code>ScannedCount</code> is the number of matching items before the filter was applied.</p>
    /// <p>If you did not use a filter in the request, then <code>Count</code> and <code>ScannedCount</code> are the same.</p>
    pub fn get_count(&self) -> &::std::option::Option<i32> {
        &self.count
    }
    /// <p>The number of items evaluated, before any <code>QueryFilter</code> is applied. A high <code>ScannedCount</code> value with few, or no, <code>Count</code> results indicates an inefficient <code>Query</code> operation. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Count">Count and ScannedCount</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    /// <p>If you did not use a filter in the request, then <code>ScannedCount</code> is the same as <code>Count</code>.</p>
    pub fn scanned_count(mut self, input: i32) -> Self {
        self.scanned_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of items evaluated, before any <code>QueryFilter</code> is applied. A high <code>ScannedCount</code> value with few, or no, <code>Count</code> results indicates an inefficient <code>Query</code> operation. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Count">Count and ScannedCount</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    /// <p>If you did not use a filter in the request, then <code>ScannedCount</code> is the same as <code>Count</code>.</p>
    pub fn set_scanned_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.scanned_count = input;
        self
    }
    /// <p>The number of items evaluated, before any <code>QueryFilter</code> is applied. A high <code>ScannedCount</code> value with few, or no, <code>Count</code> results indicates an inefficient <code>Query</code> operation. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Scan.html#Scan.Count">Count and ScannedCount</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    /// <p>If you did not use a filter in the request, then <code>ScannedCount</code> is the same as <code>Count</code>.</p>
    pub fn get_scanned_count(&self) -> &::std::option::Option<i32> {
        &self.scanned_count
    }
    /// Adds a key-value pair to `last_evaluated_key`.
    ///
    /// To override the contents of this collection use [`set_last_evaluated_key`](Self::set_last_evaluated_key).
    ///
    /// <p>The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request.</p>
    /// <p>If <code>LastEvaluatedKey</code> is empty, then the "last page" of results has been processed and there is no more data to be retrieved.</p>
    /// <p>If <code>LastEvaluatedKey</code> is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when <code>LastEvaluatedKey</code> is empty.</p>
    pub fn last_evaluated_key(mut self, k: impl ::std::convert::Into<::std::string::String>, v: crate::types::AttributeValue) -> Self {
        let mut hash_map = self.last_evaluated_key.unwrap_or_default();
        hash_map.insert(k.into(), v);
        self.last_evaluated_key = ::std::option::Option::Some(hash_map);
        self
    }
    /// <p>The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request.</p>
    /// <p>If <code>LastEvaluatedKey</code> is empty, then the "last page" of results has been processed and there is no more data to be retrieved.</p>
    /// <p>If <code>LastEvaluatedKey</code> is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when <code>LastEvaluatedKey</code> is empty.</p>
    pub fn set_last_evaluated_key(
        mut self,
        input: ::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>>,
    ) -> Self {
        self.last_evaluated_key = input;
        self
    }
    /// <p>The primary key of the item where the operation stopped, inclusive of the previous result set. Use this value to start a new operation, excluding this value in the new request.</p>
    /// <p>If <code>LastEvaluatedKey</code> is empty, then the "last page" of results has been processed and there is no more data to be retrieved.</p>
    /// <p>If <code>LastEvaluatedKey</code> is not empty, it does not necessarily mean that there is more data in the result set. The only way to know when you have reached the end of the result set is when <code>LastEvaluatedKey</code> is empty.</p>
    pub fn get_last_evaluated_key(&self) -> &::std::option::Option<::std::collections::HashMap<::std::string::String, crate::types::AttributeValue>> {
        &self.last_evaluated_key
    }
    /// <p>The capacity units consumed by the <code>Query</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#read-operation-consumption">Capacity unit consumption for read operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn consumed_capacity(mut self, input: crate::types::ConsumedCapacity) -> Self {
        self.consumed_capacity = ::std::option::Option::Some(input);
        self
    }
    /// <p>The capacity units consumed by the <code>Query</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#read-operation-consumption">Capacity unit consumption for read operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn set_consumed_capacity(mut self, input: ::std::option::Option<crate::types::ConsumedCapacity>) -> Self {
        self.consumed_capacity = input;
        self
    }
    /// <p>The capacity units consumed by the <code>Query</code> operation. The data returned includes the total provisioned throughput consumed, along with statistics for the table and any indexes involved in the operation. <code>ConsumedCapacity</code> is only returned if the <code>ReturnConsumedCapacity</code> parameter was specified. For more information, see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/read-write-operations.html#read-operation-consumption">Capacity unit consumption for read operations</a> in the <i>Amazon DynamoDB Developer Guide</i>.</p>
    pub fn get_consumed_capacity(&self) -> &::std::option::Option<crate::types::ConsumedCapacity> {
        &self.consumed_capacity
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`QueryOutput`](crate::operation::query::QueryOutput).
    pub fn build(self) -> crate::operation::query::QueryOutput {
        crate::operation::query::QueryOutput {
            items: self.items,
            count: self.count.unwrap_or_default(),
            scanned_count: self.scanned_count.unwrap_or_default(),
            last_evaluated_key: self.last_evaluated_key,
            consumed_capacity: self.consumed_capacity,
            _request_id: self._request_id,
        }
    }
}
