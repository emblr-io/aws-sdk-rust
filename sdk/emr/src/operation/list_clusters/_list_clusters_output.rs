// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This contains a ClusterSummaryList with the cluster details; for example, the cluster IDs, names, and status.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListClustersOutput {
    /// <p>The list of clusters for the account based on the given filters.</p>
    pub clusters: ::std::option::Option<::std::vec::Vec<crate::types::ClusterSummary>>,
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListClustersOutput {
    /// <p>The list of clusters for the account based on the given filters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.clusters.is_none()`.
    pub fn clusters(&self) -> &[crate::types::ClusterSummary] {
        self.clusters.as_deref().unwrap_or_default()
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn marker(&self) -> ::std::option::Option<&str> {
        self.marker.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for ListClustersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl ListClustersOutput {
    /// Creates a new builder-style object to manufacture [`ListClustersOutput`](crate::operation::list_clusters::ListClustersOutput).
    pub fn builder() -> crate::operation::list_clusters::builders::ListClustersOutputBuilder {
        crate::operation::list_clusters::builders::ListClustersOutputBuilder::default()
    }
}

/// A builder for [`ListClustersOutput`](crate::operation::list_clusters::ListClustersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListClustersOutputBuilder {
    pub(crate) clusters: ::std::option::Option<::std::vec::Vec<crate::types::ClusterSummary>>,
    pub(crate) marker: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl ListClustersOutputBuilder {
    /// Appends an item to `clusters`.
    ///
    /// To override the contents of this collection use [`set_clusters`](Self::set_clusters).
    ///
    /// <p>The list of clusters for the account based on the given filters.</p>
    pub fn clusters(mut self, input: crate::types::ClusterSummary) -> Self {
        let mut v = self.clusters.unwrap_or_default();
        v.push(input);
        self.clusters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of clusters for the account based on the given filters.</p>
    pub fn set_clusters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ClusterSummary>>) -> Self {
        self.clusters = input;
        self
    }
    /// <p>The list of clusters for the account based on the given filters.</p>
    pub fn get_clusters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ClusterSummary>> {
        &self.clusters
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn marker(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.marker = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
    pub fn set_marker(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.marker = input;
        self
    }
    /// <p>The pagination token that indicates the next set of results to retrieve.</p>
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
    /// Consumes the builder and constructs a [`ListClustersOutput`](crate::operation::list_clusters::ListClustersOutput).
    pub fn build(self) -> crate::operation::list_clusters::ListClustersOutput {
        crate::operation::list_clusters::ListClustersOutput {
            clusters: self.clusters,
            marker: self.marker,
            _request_id: self._request_id,
        }
    }
}
