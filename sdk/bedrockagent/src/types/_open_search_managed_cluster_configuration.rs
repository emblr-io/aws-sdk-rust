// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains details about the Managed Cluster configuration of the knowledge base in Amazon OpenSearch Service. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-setup-osm.html">Create a vector index in OpenSearch Managed Cluster</a>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct OpenSearchManagedClusterConfiguration {
    /// <p>The endpoint URL the OpenSearch domain.</p>
    pub domain_endpoint: ::std::string::String,
    /// <p>The Amazon Resource Name (ARN) of the OpenSearch domain.</p>
    pub domain_arn: ::std::string::String,
    /// <p>The name of the vector store.</p>
    pub vector_index_name: ::std::string::String,
    /// <p>Contains the names of the fields to which to map information about the vector store.</p>
    pub field_mapping: ::std::option::Option<crate::types::OpenSearchManagedClusterFieldMapping>,
}
impl OpenSearchManagedClusterConfiguration {
    /// <p>The endpoint URL the OpenSearch domain.</p>
    pub fn domain_endpoint(&self) -> &str {
        use std::ops::Deref;
        self.domain_endpoint.deref()
    }
    /// <p>The Amazon Resource Name (ARN) of the OpenSearch domain.</p>
    pub fn domain_arn(&self) -> &str {
        use std::ops::Deref;
        self.domain_arn.deref()
    }
    /// <p>The name of the vector store.</p>
    pub fn vector_index_name(&self) -> &str {
        use std::ops::Deref;
        self.vector_index_name.deref()
    }
    /// <p>Contains the names of the fields to which to map information about the vector store.</p>
    pub fn field_mapping(&self) -> ::std::option::Option<&crate::types::OpenSearchManagedClusterFieldMapping> {
        self.field_mapping.as_ref()
    }
}
impl ::std::fmt::Debug for OpenSearchManagedClusterConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OpenSearchManagedClusterConfiguration");
        formatter.field("domain_endpoint", &self.domain_endpoint);
        formatter.field("domain_arn", &self.domain_arn);
        formatter.field("vector_index_name", &"*** Sensitive Data Redacted ***");
        formatter.field("field_mapping", &self.field_mapping);
        formatter.finish()
    }
}
impl OpenSearchManagedClusterConfiguration {
    /// Creates a new builder-style object to manufacture [`OpenSearchManagedClusterConfiguration`](crate::types::OpenSearchManagedClusterConfiguration).
    pub fn builder() -> crate::types::builders::OpenSearchManagedClusterConfigurationBuilder {
        crate::types::builders::OpenSearchManagedClusterConfigurationBuilder::default()
    }
}

/// A builder for [`OpenSearchManagedClusterConfiguration`](crate::types::OpenSearchManagedClusterConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct OpenSearchManagedClusterConfigurationBuilder {
    pub(crate) domain_endpoint: ::std::option::Option<::std::string::String>,
    pub(crate) domain_arn: ::std::option::Option<::std::string::String>,
    pub(crate) vector_index_name: ::std::option::Option<::std::string::String>,
    pub(crate) field_mapping: ::std::option::Option<crate::types::OpenSearchManagedClusterFieldMapping>,
}
impl OpenSearchManagedClusterConfigurationBuilder {
    /// <p>The endpoint URL the OpenSearch domain.</p>
    /// This field is required.
    pub fn domain_endpoint(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_endpoint = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The endpoint URL the OpenSearch domain.</p>
    pub fn set_domain_endpoint(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_endpoint = input;
        self
    }
    /// <p>The endpoint URL the OpenSearch domain.</p>
    pub fn get_domain_endpoint(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_endpoint
    }
    /// <p>The Amazon Resource Name (ARN) of the OpenSearch domain.</p>
    /// This field is required.
    pub fn domain_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the OpenSearch domain.</p>
    pub fn set_domain_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the OpenSearch domain.</p>
    pub fn get_domain_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_arn
    }
    /// <p>The name of the vector store.</p>
    /// This field is required.
    pub fn vector_index_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.vector_index_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the vector store.</p>
    pub fn set_vector_index_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.vector_index_name = input;
        self
    }
    /// <p>The name of the vector store.</p>
    pub fn get_vector_index_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.vector_index_name
    }
    /// <p>Contains the names of the fields to which to map information about the vector store.</p>
    /// This field is required.
    pub fn field_mapping(mut self, input: crate::types::OpenSearchManagedClusterFieldMapping) -> Self {
        self.field_mapping = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the names of the fields to which to map information about the vector store.</p>
    pub fn set_field_mapping(mut self, input: ::std::option::Option<crate::types::OpenSearchManagedClusterFieldMapping>) -> Self {
        self.field_mapping = input;
        self
    }
    /// <p>Contains the names of the fields to which to map information about the vector store.</p>
    pub fn get_field_mapping(&self) -> &::std::option::Option<crate::types::OpenSearchManagedClusterFieldMapping> {
        &self.field_mapping
    }
    /// Consumes the builder and constructs a [`OpenSearchManagedClusterConfiguration`](crate::types::OpenSearchManagedClusterConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`domain_endpoint`](crate::types::builders::OpenSearchManagedClusterConfigurationBuilder::domain_endpoint)
    /// - [`domain_arn`](crate::types::builders::OpenSearchManagedClusterConfigurationBuilder::domain_arn)
    /// - [`vector_index_name`](crate::types::builders::OpenSearchManagedClusterConfigurationBuilder::vector_index_name)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::OpenSearchManagedClusterConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::OpenSearchManagedClusterConfiguration {
            domain_endpoint: self.domain_endpoint.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_endpoint",
                    "domain_endpoint was not specified but it is required when building OpenSearchManagedClusterConfiguration",
                )
            })?,
            domain_arn: self.domain_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "domain_arn",
                    "domain_arn was not specified but it is required when building OpenSearchManagedClusterConfiguration",
                )
            })?,
            vector_index_name: self.vector_index_name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "vector_index_name",
                    "vector_index_name was not specified but it is required when building OpenSearchManagedClusterConfiguration",
                )
            })?,
            field_mapping: self.field_mapping,
        })
    }
}
impl ::std::fmt::Debug for OpenSearchManagedClusterConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("OpenSearchManagedClusterConfigurationBuilder");
        formatter.field("domain_endpoint", &self.domain_endpoint);
        formatter.field("domain_arn", &self.domain_arn);
        formatter.field("vector_index_name", &"*** Sensitive Data Redacted ***");
        formatter.field("field_mapping", &self.field_mapping);
        formatter.finish()
    }
}
