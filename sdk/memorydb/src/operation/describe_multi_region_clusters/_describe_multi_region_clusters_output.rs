// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeMultiRegionClustersOutput {
    /// <p>A token to use to retrieve the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>A list of multi-Region clusters.</p>
    pub multi_region_clusters: ::std::option::Option<::std::vec::Vec<crate::types::MultiRegionCluster>>,
    _request_id: Option<String>,
}
impl DescribeMultiRegionClustersOutput {
    /// <p>A token to use to retrieve the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>A list of multi-Region clusters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.multi_region_clusters.is_none()`.
    pub fn multi_region_clusters(&self) -> &[crate::types::MultiRegionCluster] {
        self.multi_region_clusters.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeMultiRegionClustersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeMultiRegionClustersOutput {
    /// Creates a new builder-style object to manufacture [`DescribeMultiRegionClustersOutput`](crate::operation::describe_multi_region_clusters::DescribeMultiRegionClustersOutput).
    pub fn builder() -> crate::operation::describe_multi_region_clusters::builders::DescribeMultiRegionClustersOutputBuilder {
        crate::operation::describe_multi_region_clusters::builders::DescribeMultiRegionClustersOutputBuilder::default()
    }
}

/// A builder for [`DescribeMultiRegionClustersOutput`](crate::operation::describe_multi_region_clusters::DescribeMultiRegionClustersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeMultiRegionClustersOutputBuilder {
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) multi_region_clusters: ::std::option::Option<::std::vec::Vec<crate::types::MultiRegionCluster>>,
    _request_id: Option<String>,
}
impl DescribeMultiRegionClustersOutputBuilder {
    /// <p>A token to use to retrieve the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to use to retrieve the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to use to retrieve the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Appends an item to `multi_region_clusters`.
    ///
    /// To override the contents of this collection use [`set_multi_region_clusters`](Self::set_multi_region_clusters).
    ///
    /// <p>A list of multi-Region clusters.</p>
    pub fn multi_region_clusters(mut self, input: crate::types::MultiRegionCluster) -> Self {
        let mut v = self.multi_region_clusters.unwrap_or_default();
        v.push(input);
        self.multi_region_clusters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of multi-Region clusters.</p>
    pub fn set_multi_region_clusters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MultiRegionCluster>>) -> Self {
        self.multi_region_clusters = input;
        self
    }
    /// <p>A list of multi-Region clusters.</p>
    pub fn get_multi_region_clusters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MultiRegionCluster>> {
        &self.multi_region_clusters
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeMultiRegionClustersOutput`](crate::operation::describe_multi_region_clusters::DescribeMultiRegionClustersOutput).
    pub fn build(self) -> crate::operation::describe_multi_region_clusters::DescribeMultiRegionClustersOutput {
        crate::operation::describe_multi_region_clusters::DescribeMultiRegionClustersOutput {
            next_token: self.next_token,
            multi_region_clusters: self.multi_region_clusters,
            _request_id: self._request_id,
        }
    }
}
