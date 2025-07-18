// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeOrderableReplicationInstancesOutput {
    /// <p>The order-able replication instances available.</p>
    pub orderable_replication_instances: ::std::option::Option<::std::vec::Vec<crate::types::OrderableReplicationInstance>>,
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeOrderableReplicationInstancesOutput {
    /// <p>The order-able replication instances available.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.orderable_replication_instances.is_none()`.
    pub fn orderable_replication_instances(&self) -> &[crate::types::OrderableReplicationInstance] {
        self.orderable_replication_instances.as_deref().unwrap_or_default()
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeOrderableReplicationInstancesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeOrderableReplicationInstancesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeOrderableReplicationInstancesOutput`](crate::operation::describe_orderable_replication_instances::DescribeOrderableReplicationInstancesOutput).
    pub fn builder() -> crate::operation::describe_orderable_replication_instances::builders::DescribeOrderableReplicationInstancesOutputBuilder {
        crate::operation::describe_orderable_replication_instances::builders::DescribeOrderableReplicationInstancesOutputBuilder::default()
    }
}

/// A builder for [`DescribeOrderableReplicationInstancesOutput`](crate::operation::describe_orderable_replication_instances::DescribeOrderableReplicationInstancesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeOrderableReplicationInstancesOutputBuilder {
    pub(crate) orderable_replication_instances: ::std::option::Option<::std::vec::Vec<crate::types::OrderableReplicationInstance>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeOrderableReplicationInstancesOutputBuilder {
    /// Appends an item to `orderable_replication_instances`.
    ///
    /// To override the contents of this collection use [`set_orderable_replication_instances`](Self::set_orderable_replication_instances).
    ///
    /// <p>The order-able replication instances available.</p>
    pub fn orderable_replication_instances(mut self, input: crate::types::OrderableReplicationInstance) -> Self {
        let mut v = self.orderable_replication_instances.unwrap_or_default();
        v.push(input);
        self.orderable_replication_instances = ::std::option::Option::Some(v);
        self
    }
    /// <p>The order-able replication instances available.</p>
    pub fn set_orderable_replication_instances(
        mut self,
        input: ::std::option::Option<::std::vec::Vec<crate::types::OrderableReplicationInstance>>,
    ) -> Self {
        self.orderable_replication_instances = input;
        self
    }
    /// <p>The order-able replication instances available.</p>
    pub fn get_orderable_replication_instances(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::OrderableReplicationInstance>> {
        &self.orderable_replication_instances
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional pagination token provided by a previous request. If this parameter is specified, the response includes only records beyond the marker, up to the value specified by <code>MaxRecords</code>.</p>
    pub fn get_marker(&self) -> &::std::option::Option<::std::string::String> {
        &self.marker
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeOrderableReplicationInstancesOutput`](crate::operation::describe_orderable_replication_instances::DescribeOrderableReplicationInstancesOutput).
    pub fn build(self) -> crate::operation::describe_orderable_replication_instances::DescribeOrderableReplicationInstancesOutput {
        crate::operation::describe_orderable_replication_instances::DescribeOrderableReplicationInstancesOutput {
            orderable_replication_instances: self.orderable_replication_instances,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
