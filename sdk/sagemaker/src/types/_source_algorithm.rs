// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Specifies an algorithm that was used to create the model package. The algorithm must be either an algorithm resource in your SageMaker account or an algorithm in Amazon Web Services Marketplace that you are subscribed to.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct SourceAlgorithm {
    /// <p>The Amazon S3 path where the model artifacts, which result from model training, are stored. This path must point to a single <code>gzip</code> compressed tar archive (<code>.tar.gz</code> suffix).</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same Amazon Web Services region as the algorithm.</p>
    /// </note>
    pub model_data_url: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the location of ML model data to deploy during endpoint creation.</p>
    pub model_data_source: ::std::option::Option<crate::types::ModelDataSource>,
    /// <p>The ETag associated with Model Data URL.</p>
    pub model_data_e_tag: ::std::option::Option<::std::string::String>,
    /// <p>The name of an algorithm that was used to create the model package. The algorithm must be either an algorithm resource in your SageMaker account or an algorithm in Amazon Web Services Marketplace that you are subscribed to.</p>
    pub algorithm_name: ::std::option::Option<::std::string::String>,
}
impl SourceAlgorithm {
    /// <p>The Amazon S3 path where the model artifacts, which result from model training, are stored. This path must point to a single <code>gzip</code> compressed tar archive (<code>.tar.gz</code> suffix).</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same Amazon Web Services region as the algorithm.</p>
    /// </note>
    pub fn model_data_url(&self) -> ::std::option::Option<&str> {
        self.model_data_url.as_deref()
    }
    /// <p>Specifies the location of ML model data to deploy during endpoint creation.</p>
    pub fn model_data_source(&self) -> ::std::option::Option<&crate::types::ModelDataSource> {
        self.model_data_source.as_ref()
    }
    /// <p>The ETag associated with Model Data URL.</p>
    pub fn model_data_e_tag(&self) -> ::std::option::Option<&str> {
        self.model_data_e_tag.as_deref()
    }
    /// <p>The name of an algorithm that was used to create the model package. The algorithm must be either an algorithm resource in your SageMaker account or an algorithm in Amazon Web Services Marketplace that you are subscribed to.</p>
    pub fn algorithm_name(&self) -> ::std::option::Option<&str> {
        self.algorithm_name.as_deref()
    }
}
impl SourceAlgorithm {
    /// Creates a new builder-style object to manufacture [`SourceAlgorithm`](crate::types::SourceAlgorithm).
    pub fn builder() -> crate::types::builders::SourceAlgorithmBuilder {
        crate::types::builders::SourceAlgorithmBuilder::default()
    }
}

/// A builder for [`SourceAlgorithm`](crate::types::SourceAlgorithm).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct SourceAlgorithmBuilder {
    pub(crate) model_data_url: ::std::option::Option<::std::string::String>,
    pub(crate) model_data_source: ::std::option::Option<crate::types::ModelDataSource>,
    pub(crate) model_data_e_tag: ::std::option::Option<::std::string::String>,
    pub(crate) algorithm_name: ::std::option::Option<::std::string::String>,
}
impl SourceAlgorithmBuilder {
    /// <p>The Amazon S3 path where the model artifacts, which result from model training, are stored. This path must point to a single <code>gzip</code> compressed tar archive (<code>.tar.gz</code> suffix).</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same Amazon Web Services region as the algorithm.</p>
    /// </note>
    pub fn model_data_url(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_data_url = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon S3 path where the model artifacts, which result from model training, are stored. This path must point to a single <code>gzip</code> compressed tar archive (<code>.tar.gz</code> suffix).</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same Amazon Web Services region as the algorithm.</p>
    /// </note>
    pub fn set_model_data_url(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_data_url = input;
        self
    }
    /// <p>The Amazon S3 path where the model artifacts, which result from model training, are stored. This path must point to a single <code>gzip</code> compressed tar archive (<code>.tar.gz</code> suffix).</p><note>
    /// <p>The model artifacts must be in an S3 bucket that is in the same Amazon Web Services region as the algorithm.</p>
    /// </note>
    pub fn get_model_data_url(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_data_url
    }
    /// <p>Specifies the location of ML model data to deploy during endpoint creation.</p>
    pub fn model_data_source(mut self, input: crate::types::ModelDataSource) -> Self {
        self.model_data_source = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies the location of ML model data to deploy during endpoint creation.</p>
    pub fn set_model_data_source(mut self, input: ::std::option::Option<crate::types::ModelDataSource>) -> Self {
        self.model_data_source = input;
        self
    }
    /// <p>Specifies the location of ML model data to deploy during endpoint creation.</p>
    pub fn get_model_data_source(&self) -> &::std::option::Option<crate::types::ModelDataSource> {
        &self.model_data_source
    }
    /// <p>The ETag associated with Model Data URL.</p>
    pub fn model_data_e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.model_data_e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ETag associated with Model Data URL.</p>
    pub fn set_model_data_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.model_data_e_tag = input;
        self
    }
    /// <p>The ETag associated with Model Data URL.</p>
    pub fn get_model_data_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.model_data_e_tag
    }
    /// <p>The name of an algorithm that was used to create the model package. The algorithm must be either an algorithm resource in your SageMaker account or an algorithm in Amazon Web Services Marketplace that you are subscribed to.</p>
    /// This field is required.
    pub fn algorithm_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.algorithm_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of an algorithm that was used to create the model package. The algorithm must be either an algorithm resource in your SageMaker account or an algorithm in Amazon Web Services Marketplace that you are subscribed to.</p>
    pub fn set_algorithm_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.algorithm_name = input;
        self
    }
    /// <p>The name of an algorithm that was used to create the model package. The algorithm must be either an algorithm resource in your SageMaker account or an algorithm in Amazon Web Services Marketplace that you are subscribed to.</p>
    pub fn get_algorithm_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.algorithm_name
    }
    /// Consumes the builder and constructs a [`SourceAlgorithm`](crate::types::SourceAlgorithm).
    pub fn build(self) -> crate::types::SourceAlgorithm {
        crate::types::SourceAlgorithm {
            model_data_url: self.model_data_url,
            model_data_source: self.model_data_source,
            model_data_e_tag: self.model_data_e_tag,
            algorithm_name: self.algorithm_name,
        }
    }
}
