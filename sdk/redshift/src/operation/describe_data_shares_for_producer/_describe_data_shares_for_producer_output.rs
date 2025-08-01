// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeDataSharesForProducerOutput {
    /// <p>Shows the results of datashares available for producers.</p>
    pub data_shares: ::std::option::Option<::std::vec::Vec<crate::types::DataShare>>,
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeDataSharesForProducer</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDataSharesForProducerOutput {
    /// <p>Shows the results of datashares available for producers.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.data_shares.is_none()`.
    pub fn data_shares(&self) -> &[crate::types::DataShare] {
        self.data_shares.as_deref().unwrap_or_default()
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeDataSharesForProducer</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeDataSharesForProducerOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeDataSharesForProducerOutput {
    /// Creates a new builder-style object to manufacture [`DescribeDataSharesForProducerOutput`](crate::operation::describe_data_shares_for_producer::DescribeDataSharesForProducerOutput).
    pub fn builder() -> crate::operation::describe_data_shares_for_producer::builders::DescribeDataSharesForProducerOutputBuilder {
        crate::operation::describe_data_shares_for_producer::builders::DescribeDataSharesForProducerOutputBuilder::default()
    }
}

/// A builder for [`DescribeDataSharesForProducerOutput`](crate::operation::describe_data_shares_for_producer::DescribeDataSharesForProducerOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeDataSharesForProducerOutputBuilder {
    pub(crate) data_shares: ::std::option::Option<::std::vec::Vec<crate::types::DataShare>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeDataSharesForProducerOutputBuilder {
    /// Appends an item to `data_shares`.
    ///
    /// To override the contents of this collection use [`set_data_shares`](Self::set_data_shares).
    ///
    /// <p>Shows the results of datashares available for producers.</p>
    pub fn data_shares(mut self, input: crate::types::DataShare) -> Self {
        let mut v = self.data_shares.unwrap_or_default();
        v.push(input);
        self.data_shares = ::std::option::Option::Some(v);
        self
    }
    /// <p>Shows the results of datashares available for producers.</p>
    pub fn set_data_shares(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::DataShare>>) -> Self {
        self.data_shares = input;
        self
    }
    /// <p>Shows the results of datashares available for producers.</p>
    pub fn get_data_shares(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::DataShare>> {
        &self.data_shares
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeDataSharesForProducer</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeDataSharesForProducer</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>An optional parameter that specifies the starting point to return a set of response records. When the results of a <code>DescribeDataSharesForProducer</code> request exceed the value specified in <code>MaxRecords</code>, Amazon Web Services returns a value in the <code>Marker</code> field of the response. You can retrieve the next set of response records by providing the returned marker value in the <code>Marker</code> parameter and retrying the request.</p>
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
    /// Consumes the builder and constructs a [`DescribeDataSharesForProducerOutput`](crate::operation::describe_data_shares_for_producer::DescribeDataSharesForProducerOutput).
    pub fn build(self) -> crate::operation::describe_data_shares_for_producer::DescribeDataSharesForProducerOutput {
        crate::operation::describe_data_shares_for_producer::DescribeDataSharesForProducerOutput {
            data_shares: self.data_shares,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
