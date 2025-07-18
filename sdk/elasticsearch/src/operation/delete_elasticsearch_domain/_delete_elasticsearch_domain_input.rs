// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>DeleteElasticsearchDomain</code></code> operation. Specifies the name of the Elasticsearch domain that you want to delete.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteElasticsearchDomainInput {
    /// <p>The name of the Elasticsearch domain that you want to permanently delete.</p>
    pub domain_name: ::std::option::Option<::std::string::String>,
}
impl DeleteElasticsearchDomainInput {
    /// <p>The name of the Elasticsearch domain that you want to permanently delete.</p>
    pub fn domain_name(&self) -> ::std::option::Option<&str> {
        self.domain_name.as_deref()
    }
}
impl DeleteElasticsearchDomainInput {
    /// Creates a new builder-style object to manufacture [`DeleteElasticsearchDomainInput`](crate::operation::delete_elasticsearch_domain::DeleteElasticsearchDomainInput).
    pub fn builder() -> crate::operation::delete_elasticsearch_domain::builders::DeleteElasticsearchDomainInputBuilder {
        crate::operation::delete_elasticsearch_domain::builders::DeleteElasticsearchDomainInputBuilder::default()
    }
}

/// A builder for [`DeleteElasticsearchDomainInput`](crate::operation::delete_elasticsearch_domain::DeleteElasticsearchDomainInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteElasticsearchDomainInputBuilder {
    pub(crate) domain_name: ::std::option::Option<::std::string::String>,
}
impl DeleteElasticsearchDomainInputBuilder {
    /// <p>The name of the Elasticsearch domain that you want to permanently delete.</p>
    /// This field is required.
    pub fn domain_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the Elasticsearch domain that you want to permanently delete.</p>
    pub fn set_domain_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_name = input;
        self
    }
    /// <p>The name of the Elasticsearch domain that you want to permanently delete.</p>
    pub fn get_domain_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_name
    }
    /// Consumes the builder and constructs a [`DeleteElasticsearchDomainInput`](crate::operation::delete_elasticsearch_domain::DeleteElasticsearchDomainInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::delete_elasticsearch_domain::DeleteElasticsearchDomainInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::delete_elasticsearch_domain::DeleteElasticsearchDomainInput {
            domain_name: self.domain_name,
        })
    }
}
