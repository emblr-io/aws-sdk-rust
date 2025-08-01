// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>This structure contains information about the OpenSearch Service collection used for this integration. An OpenSearch Service collection is a logical grouping of one or more indexes that represent an analytics workload. For more information, see <a href="https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-collections.html">Creating and managing OpenSearch Service Serverless collections</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct OpenSearchCollection {
    /// <p>The endpoint of the collection.</p>
    pub collection_endpoint: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the collection.</p>
    pub collection_arn: ::std::option::Option<::std::string::String>,
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchCollection {
    /// <p>The endpoint of the collection.</p>
    pub fn collection_endpoint(&self) -> ::std::option::Option<&str> {
        self.collection_endpoint.as_deref()
    }
    /// <p>The ARN of the collection.</p>
    pub fn collection_arn(&self) -> ::std::option::Option<&str> {
        self.collection_arn.as_deref()
    }
    /// <p>This structure contains information about the status of this OpenSearch Service resource.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::OpenSearchResourceStatus> {
        self.status.as_ref()
    }
}
impl OpenSearchCollection {
    /// Creates a new builder-style object to manufacture [`OpenSearchCollection`](crate::types::OpenSearchCollection).
    pub fn builder() -> crate::types::builders::OpenSearchCollectionBuilder {
        crate::types::builders::OpenSearchCollectionBuilder::default()
    }
}

/// A builder for [`OpenSearchCollection`](crate::types::OpenSearchCollection).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct OpenSearchCollectionBuilder {
    pub(crate) collection_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) collection_arn: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::OpenSearchResourceStatus>,
}
impl OpenSearchCollectionBuilder {
    /// <p>The endpoint of the collection.</p>
    pub fn collection_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collection_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint of the collection.</p>
    pub fn set_collection_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collection_endpoint = input;
        self
    }
    /// <p>The endpoint of the collection.</p>
    pub fn get_collection_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.collection_endpoint
    }
    /// <p>The ARN of the collection.</p>
    pub fn collection_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.collection_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the collection.</p>
    pub fn set_collection_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.collection_arn = input;
        self
    }
    /// <p>The ARN of the collection.</p>
    pub fn get_collection_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.collection_arn
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
    /// Consumes the builder and constructs a [`OpenSearchCollection`](crate::types::OpenSearchCollection).
    pub fn build(self) -> crate::types::OpenSearchCollection {
        crate::types::OpenSearchCollection {
            collection_endpoint: self.collection_endpoint,
            collection_arn: self.collection_arn,
            status: self.status,
        }
    }
}
