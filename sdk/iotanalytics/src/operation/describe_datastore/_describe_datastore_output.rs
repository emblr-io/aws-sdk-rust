// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDatastoreOutput {
    /// <p>Information about the data store.</p>
    pub datastore: ::std::option::Option<crate::types::Datastore>,
    /// <p>Additional statistical information about the data store. Included if the <code>includeStatistics</code> parameter is set to <code>true</code> in the request.</p>
    pub statistics: ::std::option::Option<crate::types::DatastoreStatistics>,
    _request_id: Option<String>,
}
impl DescribeDatastoreOutput {
    /// <p>Information about the data store.</p>
    pub fn datastore(&self) -> ::std::option::Option<&crate::types::Datastore> {
        self.datastore.as_ref()
    }
    /// <p>Additional statistical information about the data store. Included if the <code>includeStatistics</code> parameter is set to <code>true</code> in the request.</p>
    pub fn statistics(&self) -> ::std::option::Option<&crate::types::DatastoreStatistics> {
        self.statistics.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDatastoreOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDatastoreOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDatastoreOutput`](crate::operation::describe_datastore::DescribeDatastoreOutput).
    pub fn builder() -> crate::operation::describe_datastore::builders::DescribeDatastoreOutputBuilder {
        crate::operation::describe_datastore::builders::DescribeDatastoreOutputBuilder::default()
    }
}

/// A builder for [`DescribeDatastoreOutput`](crate::operation::describe_datastore::DescribeDatastoreOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDatastoreOutputBuilder {
    pub(crate) datastore: ::std::option::Option<crate::types::Datastore>,
    pub(crate) statistics: ::std::option::Option<crate::types::DatastoreStatistics>,
    _request_id: Option<String>,
}
impl DescribeDatastoreOutputBuilder {
    /// <p>Information about the data store.</p>
    pub fn datastore(mut self, input: crate::types::Datastore) -> Self {
        self.datastore = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the data store.</p>
    pub fn set_datastore(mut self, input: ::std::option::Option<crate::types::Datastore>) -> Self {
        self.datastore = input;
        self
    }
    /// <p>Information about the data store.</p>
    pub fn get_datastore(&self) -> &::std::option::Option<crate::types::Datastore> {
        &self.datastore
    }
    /// <p>Additional statistical information about the data store. Included if the <code>includeStatistics</code> parameter is set to <code>true</code> in the request.</p>
    pub fn statistics(mut self, input: crate::types::DatastoreStatistics) -> Self {
        self.statistics = ::std::option::Option::Some(input);
        self
    }
    /// <p>Additional statistical information about the data store. Included if the <code>includeStatistics</code> parameter is set to <code>true</code> in the request.</p>
    pub fn set_statistics(mut self, input: ::std::option::Option<crate::types::DatastoreStatistics>) -> Self {
        self.statistics = input;
        self
    }
    /// <p>Additional statistical information about the data store. Included if the <code>includeStatistics</code> parameter is set to <code>true</code> in the request.</p>
    pub fn get_statistics(&self) -> &::std::option::Option<crate::types::DatastoreStatistics> {
        &self.statistics
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeDatastoreOutput`](crate::operation::describe_datastore::DescribeDatastoreOutput).
    pub fn build(self) -> crate::operation::describe_datastore::DescribeDatastoreOutput {
        crate::operation::describe_datastore::DescribeDatastoreOutput {
            datastore: self.datastore,
            statistics: self.statistics,
            _request_id: self._request_id,
        }
    }
}
