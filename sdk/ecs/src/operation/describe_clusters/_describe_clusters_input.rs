// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeClustersInput {
    /// <p>A list of up to 100 cluster names or full cluster Amazon Resource Name (ARN) entries. If you do not specify a cluster, the default cluster is assumed.</p>
    pub clusters: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>Determines whether to include additional information about the clusters in the response. If this field is omitted, this information isn't included.</p>
    /// <p>If <code>ATTACHMENTS</code> is specified, the attachments for the container instances or tasks within the cluster are included, for example the capacity providers.</p>
    /// <p>If <code>SETTINGS</code> is specified, the settings for the cluster are included.</p>
    /// <p>If <code>CONFIGURATIONS</code> is specified, the configuration for the cluster is included.</p>
    /// <p>If <code>STATISTICS</code> is specified, the task and service count is included, separated by launch type.</p>
    /// <p>If <code>TAGS</code> is specified, the metadata tags associated with the cluster are included.</p>
    pub include: ::std::option::Option<::std::vec::Vec<crate::types::ClusterField>>,
}
impl DescribeClustersInput {
    /// <p>A list of up to 100 cluster names or full cluster Amazon Resource Name (ARN) entries. If you do not specify a cluster, the default cluster is assumed.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.clusters.is_none()`.
    pub fn clusters(&self) -> &[::std::string::String] {
        self.clusters.as_deref().unwrap_or_default()
    }
    /// <p>Determines whether to include additional information about the clusters in the response. If this field is omitted, this information isn't included.</p>
    /// <p>If <code>ATTACHMENTS</code> is specified, the attachments for the container instances or tasks within the cluster are included, for example the capacity providers.</p>
    /// <p>If <code>SETTINGS</code> is specified, the settings for the cluster are included.</p>
    /// <p>If <code>CONFIGURATIONS</code> is specified, the configuration for the cluster is included.</p>
    /// <p>If <code>STATISTICS</code> is specified, the task and service count is included, separated by launch type.</p>
    /// <p>If <code>TAGS</code> is specified, the metadata tags associated with the cluster are included.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.include.is_none()`.
    pub fn include(&self) -> &[crate::types::ClusterField] {
        self.include.as_deref().unwrap_or_default()
    }
}
impl DescribeClustersInput {
    /// Creates a new builder-style object to manufacture [`DescribeClustersInput`](crate::operation::describe_clusters::DescribeClustersInput).
    pub fn builder() -> crate::operation::describe_clusters::builders::DescribeClustersInputBuilder {
        crate::operation::describe_clusters::builders::DescribeClustersInputBuilder::default()
    }
}

/// A builder for [`DescribeClustersInput`](crate::operation::describe_clusters::DescribeClustersInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeClustersInputBuilder {
    pub(crate) clusters: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) include: ::std::option::Option<::std::vec::Vec<crate::types::ClusterField>>,
}
impl DescribeClustersInputBuilder {
    /// Appends an item to `clusters`.
    ///
    /// To override the contents of this collection use [`set_clusters`](Self::set_clusters).
    ///
    /// <p>A list of up to 100 cluster names or full cluster Amazon Resource Name (ARN) entries. If you do not specify a cluster, the default cluster is assumed.</p>
    pub fn clusters(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.clusters.unwrap_or_default();
        v.push(input.into());
        self.clusters = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of up to 100 cluster names or full cluster Amazon Resource Name (ARN) entries. If you do not specify a cluster, the default cluster is assumed.</p>
    pub fn set_clusters(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.clusters = input;
        self
    }
    /// <p>A list of up to 100 cluster names or full cluster Amazon Resource Name (ARN) entries. If you do not specify a cluster, the default cluster is assumed.</p>
    pub fn get_clusters(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.clusters
    }
    /// Appends an item to `include`.
    ///
    /// To override the contents of this collection use [`set_include`](Self::set_include).
    ///
    /// <p>Determines whether to include additional information about the clusters in the response. If this field is omitted, this information isn't included.</p>
    /// <p>If <code>ATTACHMENTS</code> is specified, the attachments for the container instances or tasks within the cluster are included, for example the capacity providers.</p>
    /// <p>If <code>SETTINGS</code> is specified, the settings for the cluster are included.</p>
    /// <p>If <code>CONFIGURATIONS</code> is specified, the configuration for the cluster is included.</p>
    /// <p>If <code>STATISTICS</code> is specified, the task and service count is included, separated by launch type.</p>
    /// <p>If <code>TAGS</code> is specified, the metadata tags associated with the cluster are included.</p>
    pub fn include(mut self, input: crate::types::ClusterField) -> Self {
        let mut v = self.include.unwrap_or_default();
        v.push(input);
        self.include = ::std::option::Option::Some(v);
        self
    }
    /// <p>Determines whether to include additional information about the clusters in the response. If this field is omitted, this information isn't included.</p>
    /// <p>If <code>ATTACHMENTS</code> is specified, the attachments for the container instances or tasks within the cluster are included, for example the capacity providers.</p>
    /// <p>If <code>SETTINGS</code> is specified, the settings for the cluster are included.</p>
    /// <p>If <code>CONFIGURATIONS</code> is specified, the configuration for the cluster is included.</p>
    /// <p>If <code>STATISTICS</code> is specified, the task and service count is included, separated by launch type.</p>
    /// <p>If <code>TAGS</code> is specified, the metadata tags associated with the cluster are included.</p>
    pub fn set_include(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::ClusterField>>) -> Self {
        self.include = input;
        self
    }
    /// <p>Determines whether to include additional information about the clusters in the response. If this field is omitted, this information isn't included.</p>
    /// <p>If <code>ATTACHMENTS</code> is specified, the attachments for the container instances or tasks within the cluster are included, for example the capacity providers.</p>
    /// <p>If <code>SETTINGS</code> is specified, the settings for the cluster are included.</p>
    /// <p>If <code>CONFIGURATIONS</code> is specified, the configuration for the cluster is included.</p>
    /// <p>If <code>STATISTICS</code> is specified, the task and service count is included, separated by launch type.</p>
    /// <p>If <code>TAGS</code> is specified, the metadata tags associated with the cluster are included.</p>
    pub fn get_include(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::ClusterField>> {
        &self.include
    }
    /// Consumes the builder and constructs a [`DescribeClustersInput`](crate::operation::describe_clusters::DescribeClustersInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_clusters::DescribeClustersInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::describe_clusters::DescribeClustersInput {
            clusters: self.clusters,
            include: self.include,
        })
    }
}
