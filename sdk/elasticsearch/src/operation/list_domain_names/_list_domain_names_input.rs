// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Container for the parameters to the <code><code>ListDomainNames</code></code> operation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListDomainNamesInput {
    /// <p>Optional parameter to filter the output by domain engine type. Acceptable values are 'Elasticsearch' and 'OpenSearch'.</p>
    pub engine_type: ::std::option::Option<crate::types::EngineType>,
}
impl ListDomainNamesInput {
    /// <p>Optional parameter to filter the output by domain engine type. Acceptable values are 'Elasticsearch' and 'OpenSearch'.</p>
    pub fn engine_type(&self) -> ::std::option::Option<&crate::types::EngineType> {
        self.engine_type.as_ref()
    }
}
impl ListDomainNamesInput {
    /// Creates a new builder-style object to manufacture [`ListDomainNamesInput`](crate::operation::list_domain_names::ListDomainNamesInput).
    pub fn builder() -> crate::operation::list_domain_names::builders::ListDomainNamesInputBuilder {
        crate::operation::list_domain_names::builders::ListDomainNamesInputBuilder::default()
    }
}

/// A builder for [`ListDomainNamesInput`](crate::operation::list_domain_names::ListDomainNamesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListDomainNamesInputBuilder {
    pub(crate) engine_type: ::std::option::Option<crate::types::EngineType>,
}
impl ListDomainNamesInputBuilder {
    /// <p>Optional parameter to filter the output by domain engine type. Acceptable values are 'Elasticsearch' and 'OpenSearch'.</p>
    pub fn engine_type(mut self, input: crate::types::EngineType) -> Self {
        self.engine_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>Optional parameter to filter the output by domain engine type. Acceptable values are 'Elasticsearch' and 'OpenSearch'.</p>
    pub fn set_engine_type(mut self, input: ::std::option::Option<crate::types::EngineType>) -> Self {
        self.engine_type = input;
        self
    }
    /// <p>Optional parameter to filter the output by domain engine type. Acceptable values are 'Elasticsearch' and 'OpenSearch'.</p>
    pub fn get_engine_type(&self) -> &::std::option::Option<crate::types::EngineType> {
        &self.engine_type
    }
    /// Consumes the builder and constructs a [`ListDomainNamesInput`](crate::operation::list_domain_names::ListDomainNamesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_domain_names::ListDomainNamesInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::list_domain_names::ListDomainNamesInput {
            engine_type: self.engine_type,
        })
    }
}
