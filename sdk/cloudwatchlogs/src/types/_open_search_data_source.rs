// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure contains information about the OpenSearch Service data source used for this integration. This data source was created as part of the integration setup. An OpenSearch Service data source defines the source and destination for OpenSearch Service queries. It includes the role required to execute queries and write to collections.</p>
/// <p>For more information about OpenSearch Service data sources , see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/direct-query-s3-creating.html">Creating OpenSearch Service data source integrations with Amazon S3.</a></p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpenSearchDataSource {
    /// <p>The name of the OpenSearch Service data source.</p>
    pub data_source_name: ::std::option::Option<::std::string::String>,
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchDataSource {
    /// <p>The name of the OpenSearch Service data source.</p>
    pub fn data_source_name(&self) -> ::std::option::Option<&str> {
        self.data_source_name.as_deref()
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OpenSearchResourceStatus> {
        self.status.as_ref()
    }
}
impl OpenSearchDataSource {
    /// Creates a new builder-style object to manufacture [`OpenSearchDataSource`](crate::types::OpenSearchDataSource).
    pub fn builder() -> crate::types::builders::OpenSearchDataSourceBuilder {
        crate::types::builders::OpenSearchDataSourceBuilder::default()
    }
}

/// A builder for [`OpenSearchDataSource`](crate::types::OpenSearchDataSource).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpenSearchDataSourceBuilder {
    pub(crate) data_source_name: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchDataSourceBuilder {
    /// <p>The name of the OpenSearch Service data source.</p>
    pub fn data_source_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.data_source_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the OpenSearch Service data source.</p>
    pub fn set_data_source_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.data_source_name = input;
        self
    }
    /// <p>The name of the OpenSearch Service data source.</p>
    pub fn get_data_source_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.data_source_name
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn status(mut self, input: crate::types::OpenSearchResourceStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::OpenSearchResourceStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::OpenSearchResourceStatus> {
        &self.status
    }
    /// Consumes the builder and constructs a [`OpenSearchDataSource`](crate::types::OpenSearchDataSource).
    pub fn build(self) -> crate::types::OpenSearchDataSource {
        crate::types::OpenSearchDataSource {
            data_source_name: self.data_source_name,
            status: self.status,
        }
    }
}
