// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Configurations for how to perform the search query and return results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html">Query configurations</a>.</p>
/// <p>This data type is used in the following API operations:</p>
/// <ul>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_Retrieve.html#API_agent-runtime_Retrieve_RequestSyntax">Retrieve request</a> – in the <code>vectorSearchConfiguration</code> field</p></li>
/// <li>
/// <p><a href="https://docs.aws.amazon.com/bedrock/latest/APIReference/API_agent-runtime_RetrieveAndGenerate.html#API_agent-runtime_RetrieveAndGenerate_RequestSyntax">RetrieveAndGenerate request</a> – in the <code>vectorSearchConfiguration</code> field</p></li>
/// </ul>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct KnowledgeBaseVectorSearchConfiguration {
    /// <p>The number of source chunks to retrieve.</p>
    pub number_of_results: i32,
    /// <p>By default, Amazon Bedrock decides a search strategy for you. If you're using an Amazon OpenSearch Serverless vector store that contains a filterable text field, you can specify whether to query the knowledge base with a <code>HYBRID</code> search using both vector embeddings and raw text, or <code>SEMANTIC</code> search using only vector embeddings. For other vector store configurations, only <code>SEMANTIC</code> search is available. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-test.html">Test a knowledge base</a>.</p>
    pub override_search_type: ::std::option::Option<crate::types::SearchType>,
    /// <p>Specifies the filters to use on the metadata in the knowledge base data sources before returning results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html">Query configurations</a>.</p>
    pub filter: ::std::option::Option<crate::types::RetrievalFilter>,
    /// <p>Contains configurations for reranking the retrieved results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/rerank.html">Improve the relevance of query responses with a reranker model</a>.</p>
    pub reranking_configuration: ::std::option::Option<crate::types::VectorSearchRerankingConfiguration>,
    /// <p>Settings for implicit filtering.</p>
    pub implicit_filter_configuration: ::std::option::Option<crate::types::ImplicitFilterConfiguration>,
}
impl KnowledgeBaseVectorSearchConfiguration {
    /// <p>The number of source chunks to retrieve.</p>
    pub fn number_of_results(&self) -> i32 {
        self.number_of_results
    }
    /// <p>By default, Amazon Bedrock decides a search strategy for you. If you're using an Amazon OpenSearch Serverless vector store that contains a filterable text field, you can specify whether to query the knowledge base with a <code>HYBRID</code> search using both vector embeddings and raw text, or <code>SEMANTIC</code> search using only vector embeddings. For other vector store configurations, only <code>SEMANTIC</code> search is available. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-test.html">Test a knowledge base</a>.</p>
    pub fn override_search_type(&self) -> ::std::option::Option<&crate::types::SearchType> {
        self.override_search_type.as_ref()
    }
    /// <p>Specifies the filters to use on the metadata in the knowledge base data sources before returning results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html">Query configurations</a>.</p>
    pub fn filter(&self) -> ::std::option::Option<&crate::types::RetrievalFilter> {
        self.filter.as_ref()
    }
    /// <p>Contains configurations for reranking the retrieved results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/rerank.html">Improve the relevance of query responses with a reranker model</a>.</p>
    pub fn reranking_configuration(&self) -> ::std::option::Option<&crate::types::VectorSearchRerankingConfiguration> {
        self.reranking_configuration.as_ref()
    }
    /// <p>Settings for implicit filtering.</p>
    pub fn implicit_filter_configuration(&self) -> ::std::option::Option<&crate::types::ImplicitFilterConfiguration> {
        self.implicit_filter_configuration.as_ref()
    }
}
impl ::std::fmt::Debug for KnowledgeBaseVectorSearchConfiguration {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("KnowledgeBaseVectorSearchConfiguration");
        formatter.field("number_of_results", &self.number_of_results);
        formatter.field("override_search_type", &self.override_search_type);
        formatter.field("filter", &"*** Sensitive Data Redacted ***");
        formatter.field("reranking_configuration", &self.reranking_configuration);
        formatter.field("implicit_filter_configuration", &self.implicit_filter_configuration);
        formatter.finish()
    }
}
impl KnowledgeBaseVectorSearchConfiguration {
    /// Creates a new builder-style object to manufacture [`KnowledgeBaseVectorSearchConfiguration`](crate::types::KnowledgeBaseVectorSearchConfiguration).
    pub fn builder() -> crate::types::builders::KnowledgeBaseVectorSearchConfigurationBuilder {
        crate::types::builders::KnowledgeBaseVectorSearchConfigurationBuilder::default()
    }
}

/// A builder for [`KnowledgeBaseVectorSearchConfiguration`](crate::types::KnowledgeBaseVectorSearchConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct KnowledgeBaseVectorSearchConfigurationBuilder {
    pub(crate) number_of_results: ::std::option::Option<i32>,
    pub(crate) override_search_type: ::std::option::Option<crate::types::SearchType>,
    pub(crate) filter: ::std::option::Option<crate::types::RetrievalFilter>,
    pub(crate) reranking_configuration: ::std::option::Option<crate::types::VectorSearchRerankingConfiguration>,
    pub(crate) implicit_filter_configuration: ::std::option::Option<crate::types::ImplicitFilterConfiguration>,
}
impl KnowledgeBaseVectorSearchConfigurationBuilder {
    /// <p>The number of source chunks to retrieve.</p>
    pub fn number_of_results(mut self, input: i32) -> Self {
        self.number_of_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of source chunks to retrieve.</p>
    pub fn set_number_of_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.number_of_results = input;
        self
    }
    /// <p>The number of source chunks to retrieve.</p>
    pub fn get_number_of_results(&self) -> &::std::option::Option<i32> {
        &self.number_of_results
    }
    /// <p>By default, Amazon Bedrock decides a search strategy for you. If you're using an Amazon OpenSearch Serverless vector store that contains a filterable text field, you can specify whether to query the knowledge base with a <code>HYBRID</code> search using both vector embeddings and raw text, or <code>SEMANTIC</code> search using only vector embeddings. For other vector store configurations, only <code>SEMANTIC</code> search is available. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-test.html">Test a knowledge base</a>.</p>
    pub fn override_search_type(mut self, input: crate::types::SearchType) -> Self {
        self.override_search_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>By default, Amazon Bedrock decides a search strategy for you. If you're using an Amazon OpenSearch Serverless vector store that contains a filterable text field, you can specify whether to query the knowledge base with a <code>HYBRID</code> search using both vector embeddings and raw text, or <code>SEMANTIC</code> search using only vector embeddings. For other vector store configurations, only <code>SEMANTIC</code> search is available. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-test.html">Test a knowledge base</a>.</p>
    pub fn set_override_search_type(mut self, input: ::std::option::Option<crate::types::SearchType>) -> Self {
        self.override_search_type = input;
        self
    }
    /// <p>By default, Amazon Bedrock decides a search strategy for you. If you're using an Amazon OpenSearch Serverless vector store that contains a filterable text field, you can specify whether to query the knowledge base with a <code>HYBRID</code> search using both vector embeddings and raw text, or <code>SEMANTIC</code> search using only vector embeddings. For other vector store configurations, only <code>SEMANTIC</code> search is available. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/knowledge-base-test.html">Test a knowledge base</a>.</p>
    pub fn get_override_search_type(&self) -> &::std::option::Option<crate::types::SearchType> {
        &self.override_search_type
    }
    /// <p>Specifies the filters to use on the metadata in the knowledge base data sources before returning results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html">Query configurations</a>.</p>
    pub fn filter(mut self, input: crate::types::RetrievalFilter) -> Self {
        self.filter = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the filters to use on the metadata in the knowledge base data sources before returning results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html">Query configurations</a>.</p>
    pub fn set_filter(mut self, input: ::std::option::Option<crate::types::RetrievalFilter>) -> Self {
        self.filter = input;
        self
    }
    /// <p>Specifies the filters to use on the metadata in the knowledge base data sources before returning results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/kb-test-config.html">Query configurations</a>.</p>
    pub fn get_filter(&self) -> &::std::option::Option<crate::types::RetrievalFilter> {
        &self.filter
    }
    /// <p>Contains configurations for reranking the retrieved results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/rerank.html">Improve the relevance of query responses with a reranker model</a>.</p>
    pub fn reranking_configuration(mut self, input: crate::types::VectorSearchRerankingConfiguration) -> Self {
        self.reranking_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains configurations for reranking the retrieved results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/rerank.html">Improve the relevance of query responses with a reranker model</a>.</p>
    pub fn set_reranking_configuration(mut self, input: ::std::option::Option<crate::types::VectorSearchRerankingConfiguration>) -> Self {
        self.reranking_configuration = input;
        self
    }
    /// <p>Contains configurations for reranking the retrieved results. For more information, see <a href="https://docs.aws.amazon.com/bedrock/latest/userguide/rerank.html">Improve the relevance of query responses with a reranker model</a>.</p>
    pub fn get_reranking_configuration(&self) -> &::std::option::Option<crate::types::VectorSearchRerankingConfiguration> {
        &self.reranking_configuration
    }
    /// <p>Settings for implicit filtering.</p>
    pub fn implicit_filter_configuration(mut self, input: crate::types::ImplicitFilterConfiguration) -> Self {
        self.implicit_filter_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings for implicit filtering.</p>
    pub fn set_implicit_filter_configuration(mut self, input: ::std::option::Option<crate::types::ImplicitFilterConfiguration>) -> Self {
        self.implicit_filter_configuration = input;
        self
    }
    /// <p>Settings for implicit filtering.</p>
    pub fn get_implicit_filter_configuration(&self) -> &::std::option::Option<crate::types::ImplicitFilterConfiguration> {
        &self.implicit_filter_configuration
    }
    /// Consumes the builder and constructs a [`KnowledgeBaseVectorSearchConfiguration`](crate::types::KnowledgeBaseVectorSearchConfiguration).
    pub fn build(self) -> crate::types::KnowledgeBaseVectorSearchConfiguration {
        crate::types::KnowledgeBaseVectorSearchConfiguration {
            number_of_results: self.number_of_results.unwrap_or(5),
            override_search_type: self.override_search_type,
            filter: self.filter,
            reranking_configuration: self.reranking_configuration,
            implicit_filter_configuration: self.implicit_filter_configuration,
        }
    }
}
impl ::std::fmt::Debug for KnowledgeBaseVectorSearchConfigurationBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("KnowledgeBaseVectorSearchConfigurationBuilder");
        formatter.field("number_of_results", &self.number_of_results);
        formatter.field("override_search_type", &self.override_search_type);
        formatter.field("filter", &"*** Sensitive Data Redacted ***");
        formatter.field("reranking_configuration", &self.reranking_configuration);
        formatter.field("implicit_filter_configuration", &self.implicit_filter_configuration);
        formatter.finish()
    }
}
