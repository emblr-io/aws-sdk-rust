// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeClustersOutput {
    /// <p>The list of clusters.</p>
    pub clusters: ::std::option::Option<::std::vec::Vec<crate::types::Cluster>>,
    /// <p>Any failures associated with the call.</p>
    pub failures: ::std::option::Option<::std::vec::Vec<crate::types::Failure>>,
    _request_id: Option<String>,
}
impl DescribeClustersOutput {
    /// <p>The list of clusters.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.clusters.is_none()`.
    pub fn clusters(&self) -> &[crate::types::Cluster] {
        self.clusters.as_deref().unwrap_or_default()
    }
    /// <p>Any failures associated with the call.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.failures.is_none()`.
    pub fn failures(&self) -> &[crate::types::Failure] {
        self.failures.as_deref().unwrap_or_default()
    }
}
impl ::aws_types::request_id::RequestId for DescribeClustersOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeClustersOutput {
    /// Creates a new builder-style object to manufacture [`DescribeClustersOutput`](crate::operation::describe_clusters::DescribeClustersOutput).
    pub fn builder() -> crate::operation::describe_clusters::builders::DescribeClustersOutputBuilder {
        crate::operation::describe_clusters::builders::DescribeClustersOutputBuilder::default()
    }
}

/// A builder for [`DescribeClustersOutput`](crate::operation::describe_clusters::DescribeClustersOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeClustersOutputBuilder {
    pub(crate) clusters: ::std::option::Option<::std::vec::Vec<crate::types::Cluster>>,
    pub(crate) failures: ::std::option::Option<::std::vec::Vec<crate::types::Failure>>,
    _request_id: Option<String>,
}
impl DescribeClustersOutputBuilder {
    /// Appends an item to `clusters`.
    ///
    /// To override the contents of this collection use [`set_clusters`](Self::set_clusters).
    ///
    /// <p>The list of clusters.</p>
    pub fn clusters(mut self, input: crate::types::Cluster) -> Self {
        let mut v = self.clusters.unwrap_or_default();
        v.push(input);
        self.clusters = ::std::option::Option::Some(v);
        self
    }
    /// <p>The list of clusters.</p>
    pub fn set_clusters(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Cluster>>) -> Self {
        self.clusters = input;
        self
    }
    /// <p>The list of clusters.</p>
    pub fn get_clusters(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Cluster>> {
        &self.clusters
    }
    /// Appends an item to `failures`.
    ///
    /// To override the contents of this collection use [`set_failures`](Self::set_failures).
    ///
    /// <p>Any failures associated with the call.</p>
    pub fn failures(mut self, input: crate::types::Failure) -> Self {
        let mut v = self.failures.unwrap_or_default();
        v.push(input);
        self.failures = ::std::option::Option::Some(v);
        self
    }
    /// <p>Any failures associated with the call.</p>
    pub fn set_failures(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::Failure>>) -> Self {
        self.failures = input;
        self
    }
    /// <p>Any failures associated with the call.</p>
    pub fn get_failures(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::Failure>> {
        &self.failures
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeClustersOutput`](crate::operation::describe_clusters::DescribeClustersOutput).
    pub fn build(self) -> crate::operation::describe_clusters::DescribeClustersOutput {
        crate::operation::describe_clusters::DescribeClustersOutput {
            clusters: self.clusters,
            failures: self.failures,
            _request_id: self._request_id,
        }
    }
}
