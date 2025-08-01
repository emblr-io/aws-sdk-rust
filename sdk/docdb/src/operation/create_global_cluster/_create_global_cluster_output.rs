// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateGlobalClusterOutput {
    /// <p>A data type representing an Amazon DocumentDB global cluster.</p>
    pub global_cluster: ::std::option::Option<crate::types::GlobalCluster>,
    _request_id: Option<String>,
}
impl CreateGlobalClusterOutput {
    /// <p>A data type representing an Amazon DocumentDB global cluster.</p>
    pub fn global_cluster(&self) -> ::std::option::Option<&crate::types::GlobalCluster> {
        self.global_cluster.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateGlobalClusterOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateGlobalClusterOutput {
    /// Creates a new builder-style object to manufacture [`CreateGlobalClusterOutput`](crate::operation::create_global_cluster::CreateGlobalClusterOutput).
    pub fn builder() -> crate::operation::create_global_cluster::builders::CreateGlobalClusterOutputBuilder {
        crate::operation::create_global_cluster::builders::CreateGlobalClusterOutputBuilder::default()
    }
}

/// A builder for [`CreateGlobalClusterOutput`](crate::operation::create_global_cluster::CreateGlobalClusterOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateGlobalClusterOutputBuilder {
    pub(crate) global_cluster: ::std::option::Option<crate::types::GlobalCluster>,
    _request_id: Option<String>,
}
impl CreateGlobalClusterOutputBuilder {
    /// <p>A data type representing an Amazon DocumentDB global cluster.</p>
    pub fn global_cluster(mut self, input: crate::types::GlobalCluster) -> Self {
        self.global_cluster = ::std::option::Option::Some(input);
        self
    }
    /// <p>A data type representing an Amazon DocumentDB global cluster.</p>
    pub fn set_global_cluster(mut self, input: ::std::option::Option<crate::types::GlobalCluster>) -> Self {
        self.global_cluster = input;
        self
    }
    /// <p>A data type representing an Amazon DocumentDB global cluster.</p>
    pub fn get_global_cluster(&self) -> &::std::option::Option<crate::types::GlobalCluster> {
        &self.global_cluster
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateGlobalClusterOutput`](crate::operation::create_global_cluster::CreateGlobalClusterOutput).
    pub fn build(self) -> crate::operation::create_global_cluster::CreateGlobalClusterOutput {
        crate::operation::create_global_cluster::CreateGlobalClusterOutput {
            global_cluster: self.global_cluster,
            _request_id: self._request_id,
        }
    }
}
