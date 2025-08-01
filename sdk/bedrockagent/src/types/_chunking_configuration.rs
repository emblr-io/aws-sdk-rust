// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details about how to chunk the documents in the data source. A <i>chunk</i> refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ChunkingConfiguration {
    /// <p>Knowledge base can split your source data into chunks. A <i>chunk</i> refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried. You have the following options for chunking your data. If you opt for <code>NONE</code>, then you may want to pre-process your files by splitting them up such that each file corresponds to a chunk.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED_SIZE</code> – Amazon Bedrock splits your source data into chunks of the approximate size that you set in the <code>fixedSizeChunkingConfiguration</code>.</p></li>
    /// <li>
    /// <p><code>HIERARCHICAL</code> – Split documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p></li>
    /// <li>
    /// <p><code>SEMANTIC</code> – Split documents into chunks based on groups of similar content derived with natural language processing.</p></li>
    /// <li>
    /// <p><code>NONE</code> – Amazon Bedrock treats each file as one chunk. If you choose this option, you may want to pre-process your documents by splitting them into separate files.</p></li>
    /// </ul>
    pub chunking_strategy: crate::types::ChunkingStrategy,
    /// <p>Configurations for when you choose fixed-size chunking. If you set the <code>chunkingStrategy</code> as <code>NONE</code>, exclude this field.</p>
    pub fixed_size_chunking_configuration: ::std::option::Option<crate::types::FixedSizeChunkingConfiguration>,
    /// <p>Settings for hierarchical document chunking for a data source. Hierarchical chunking splits documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p>
    pub hierarchical_chunking_configuration: ::std::option::Option<crate::types::HierarchicalChunkingConfiguration>,
    /// <p>Settings for semantic document chunking for a data source. Semantic chunking splits a document into into smaller documents based on groups of similar content derived from the text with natural language processing.</p>
    pub semantic_chunking_configuration: ::std::option::Option<crate::types::SemanticChunkingConfiguration>,
}
impl ChunkingConfiguration {
    /// <p>Knowledge base can split your source data into chunks. A <i>chunk</i> refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried. You have the following options for chunking your data. If you opt for <code>NONE</code>, then you may want to pre-process your files by splitting them up such that each file corresponds to a chunk.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED_SIZE</code> – Amazon Bedrock splits your source data into chunks of the approximate size that you set in the <code>fixedSizeChunkingConfiguration</code>.</p></li>
    /// <li>
    /// <p><code>HIERARCHICAL</code> – Split documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p></li>
    /// <li>
    /// <p><code>SEMANTIC</code> – Split documents into chunks based on groups of similar content derived with natural language processing.</p></li>
    /// <li>
    /// <p><code>NONE</code> – Amazon Bedrock treats each file as one chunk. If you choose this option, you may want to pre-process your documents by splitting them into separate files.</p></li>
    /// </ul>
    pub fn chunking_strategy(&self) -> &crate::types::ChunkingStrategy {
        &self.chunking_strategy
    }
    /// <p>Configurations for when you choose fixed-size chunking. If you set the <code>chunkingStrategy</code> as <code>NONE</code>, exclude this field.</p>
    pub fn fixed_size_chunking_configuration(&self) -> ::std::option::Option<&crate::types::FixedSizeChunkingConfiguration> {
        self.fixed_size_chunking_configuration.as_ref()
    }
    /// <p>Settings for hierarchical document chunking for a data source. Hierarchical chunking splits documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p>
    pub fn hierarchical_chunking_configuration(&self) -> ::std::option::Option<&crate::types::HierarchicalChunkingConfiguration> {
        self.hierarchical_chunking_configuration.as_ref()
    }
    /// <p>Settings for semantic document chunking for a data source. Semantic chunking splits a document into into smaller documents based on groups of similar content derived from the text with natural language processing.</p>
    pub fn semantic_chunking_configuration(&self) -> ::std::option::Option<&crate::types::SemanticChunkingConfiguration> {
        self.semantic_chunking_configuration.as_ref()
    }
}
impl ChunkingConfiguration {
    /// Creates a new builder-style object to manufacture [`ChunkingConfiguration`](crate::types::ChunkingConfiguration).
    pub fn builder() -> crate::types::builders::ChunkingConfigurationBuilder {
        crate::types::builders::ChunkingConfigurationBuilder::default()
    }
}

/// A builder for [`ChunkingConfiguration`](crate::types::ChunkingConfiguration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ChunkingConfigurationBuilder {
    pub(crate) chunking_strategy: ::std::option::Option<crate::types::ChunkingStrategy>,
    pub(crate) fixed_size_chunking_configuration: ::std::option::Option<crate::types::FixedSizeChunkingConfiguration>,
    pub(crate) hierarchical_chunking_configuration: ::std::option::Option<crate::types::HierarchicalChunkingConfiguration>,
    pub(crate) semantic_chunking_configuration: ::std::option::Option<crate::types::SemanticChunkingConfiguration>,
}
impl ChunkingConfigurationBuilder {
    /// <p>Knowledge base can split your source data into chunks. A <i>chunk</i> refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried. You have the following options for chunking your data. If you opt for <code>NONE</code>, then you may want to pre-process your files by splitting them up such that each file corresponds to a chunk.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED_SIZE</code> – Amazon Bedrock splits your source data into chunks of the approximate size that you set in the <code>fixedSizeChunkingConfiguration</code>.</p></li>
    /// <li>
    /// <p><code>HIERARCHICAL</code> – Split documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p></li>
    /// <li>
    /// <p><code>SEMANTIC</code> – Split documents into chunks based on groups of similar content derived with natural language processing.</p></li>
    /// <li>
    /// <p><code>NONE</code> – Amazon Bedrock treats each file as one chunk. If you choose this option, you may want to pre-process your documents by splitting them into separate files.</p></li>
    /// </ul>
    /// This field is required.
    pub fn chunking_strategy(mut self, input: crate::types::ChunkingStrategy) -> Self {
        self.chunking_strategy = ::std::option::Option::Some(input);
        self
    }
    /// <p>Knowledge base can split your source data into chunks. A <i>chunk</i> refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried. You have the following options for chunking your data. If you opt for <code>NONE</code>, then you may want to pre-process your files by splitting them up such that each file corresponds to a chunk.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED_SIZE</code> – Amazon Bedrock splits your source data into chunks of the approximate size that you set in the <code>fixedSizeChunkingConfiguration</code>.</p></li>
    /// <li>
    /// <p><code>HIERARCHICAL</code> – Split documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p></li>
    /// <li>
    /// <p><code>SEMANTIC</code> – Split documents into chunks based on groups of similar content derived with natural language processing.</p></li>
    /// <li>
    /// <p><code>NONE</code> – Amazon Bedrock treats each file as one chunk. If you choose this option, you may want to pre-process your documents by splitting them into separate files.</p></li>
    /// </ul>
    pub fn set_chunking_strategy(mut self, input: ::std::option::Option<crate::types::ChunkingStrategy>) -> Self {
        self.chunking_strategy = input;
        self
    }
    /// <p>Knowledge base can split your source data into chunks. A <i>chunk</i> refers to an excerpt from a data source that is returned when the knowledge base that it belongs to is queried. You have the following options for chunking your data. If you opt for <code>NONE</code>, then you may want to pre-process your files by splitting them up such that each file corresponds to a chunk.</p>
    /// <ul>
    /// <li>
    /// <p><code>FIXED_SIZE</code> – Amazon Bedrock splits your source data into chunks of the approximate size that you set in the <code>fixedSizeChunkingConfiguration</code>.</p></li>
    /// <li>
    /// <p><code>HIERARCHICAL</code> – Split documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p></li>
    /// <li>
    /// <p><code>SEMANTIC</code> – Split documents into chunks based on groups of similar content derived with natural language processing.</p></li>
    /// <li>
    /// <p><code>NONE</code> – Amazon Bedrock treats each file as one chunk. If you choose this option, you may want to pre-process your documents by splitting them into separate files.</p></li>
    /// </ul>
    pub fn get_chunking_strategy(&self) -> &::std::option::Option<crate::types::ChunkingStrategy> {
        &self.chunking_strategy
    }
    /// <p>Configurations for when you choose fixed-size chunking. If you set the <code>chunkingStrategy</code> as <code>NONE</code>, exclude this field.</p>
    pub fn fixed_size_chunking_configuration(mut self, input: crate::types::FixedSizeChunkingConfiguration) -> Self {
        self.fixed_size_chunking_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Configurations for when you choose fixed-size chunking. If you set the <code>chunkingStrategy</code> as <code>NONE</code>, exclude this field.</p>
    pub fn set_fixed_size_chunking_configuration(mut self, input: ::std::option::Option<crate::types::FixedSizeChunkingConfiguration>) -> Self {
        self.fixed_size_chunking_configuration = input;
        self
    }
    /// <p>Configurations for when you choose fixed-size chunking. If you set the <code>chunkingStrategy</code> as <code>NONE</code>, exclude this field.</p>
    pub fn get_fixed_size_chunking_configuration(&self) -> &::std::option::Option<crate::types::FixedSizeChunkingConfiguration> {
        &self.fixed_size_chunking_configuration
    }
    /// <p>Settings for hierarchical document chunking for a data source. Hierarchical chunking splits documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p>
    pub fn hierarchical_chunking_configuration(mut self, input: crate::types::HierarchicalChunkingConfiguration) -> Self {
        self.hierarchical_chunking_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings for hierarchical document chunking for a data source. Hierarchical chunking splits documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p>
    pub fn set_hierarchical_chunking_configuration(mut self, input: ::std::option::Option<crate::types::HierarchicalChunkingConfiguration>) -> Self {
        self.hierarchical_chunking_configuration = input;
        self
    }
    /// <p>Settings for hierarchical document chunking for a data source. Hierarchical chunking splits documents into layers of chunks where the first layer contains large chunks, and the second layer contains smaller chunks derived from the first layer.</p>
    pub fn get_hierarchical_chunking_configuration(&self) -> &::std::option::Option<crate::types::HierarchicalChunkingConfiguration> {
        &self.hierarchical_chunking_configuration
    }
    /// <p>Settings for semantic document chunking for a data source. Semantic chunking splits a document into into smaller documents based on groups of similar content derived from the text with natural language processing.</p>
    pub fn semantic_chunking_configuration(mut self, input: crate::types::SemanticChunkingConfiguration) -> Self {
        self.semantic_chunking_configuration = ::std::option::Option::Some(input);
        self
    }
    /// <p>Settings for semantic document chunking for a data source. Semantic chunking splits a document into into smaller documents based on groups of similar content derived from the text with natural language processing.</p>
    pub fn set_semantic_chunking_configuration(mut self, input: ::std::option::Option<crate::types::SemanticChunkingConfiguration>) -> Self {
        self.semantic_chunking_configuration = input;
        self
    }
    /// <p>Settings for semantic document chunking for a data source. Semantic chunking splits a document into into smaller documents based on groups of similar content derived from the text with natural language processing.</p>
    pub fn get_semantic_chunking_configuration(&self) -> &::std::option::Option<crate::types::SemanticChunkingConfiguration> {
        &self.semantic_chunking_configuration
    }
    /// Consumes the builder and constructs a [`ChunkingConfiguration`](crate::types::ChunkingConfiguration).
    /// This method will fail if any of the following fields are not set:
    /// - [`chunking_strategy`](crate::types::builders::ChunkingConfigurationBuilder::chunking_strategy)
    pub fn build(self) -> ::std::result::Result<crate::types::ChunkingConfiguration, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::ChunkingConfiguration {
            chunking_strategy: self.chunking_strategy.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "chunking_strategy",
                    "chunking_strategy was not specified but it is required when building ChunkingConfiguration",
                )
            })?,
            fixed_size_chunking_configuration: self.fixed_size_chunking_configuration,
            hierarchical_chunking_configuration: self.hierarchical_chunking_configuration,
            semantic_chunking_configuration: self.semantic_chunking_configuration,
        })
    }
}
