// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the recommendation.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecommendationData {
    /// <p>The identifier of the recommendation.</p>
    pub recommendation_id: ::std::string::String,
    /// <p>The recommended document.</p>
    pub document: ::std::option::Option<crate::types::Document>,
    /// <p>The relevance score of the recommendation.</p>
    pub relevance_score: f64,
    /// <p>The relevance level of the recommendation.</p>
    pub relevance_level: ::std::option::Option<crate::types::RelevanceLevel>,
    /// <p>The type of recommendation.</p>
    pub r#type: ::std::option::Option<crate::types::RecommendationType>,
    /// <p>Summary of the recommended content.</p>
    pub data: ::std::option::Option<crate::types::DataSummary>,
}
impl RecommendationData {
    /// <p>The identifier of the recommendation.</p>
    pub fn recommendation_id(&self) -> &str {
        use std::ops::Deref;
        self.recommendation_id.deref()
    }
    /// <p>The recommended document.</p>
    pub fn document(&self) -> ::std::option::Option<&crate::types::Document> {
        self.document.as_ref()
    }
    /// <p>The relevance score of the recommendation.</p>
    pub fn relevance_score(&self) -> f64 {
        self.relevance_score
    }
    /// <p>The relevance level of the recommendation.</p>
    pub fn relevance_level(&self) -> ::std::option::Option<&crate::types::RelevanceLevel> {
        self.relevance_level.as_ref()
    }
    /// <p>The type of recommendation.</p>
    pub fn r#type(&self) -> ::std::option::Option<&crate::types::RecommendationType> {
        self.r#type.as_ref()
    }
    /// <p>Summary of the recommended content.</p>
    pub fn data(&self) -> ::std::option::Option<&crate::types::DataSummary> {
        self.data.as_ref()
    }
}
impl RecommendationData {
    /// Creates a new builder-style object to manufacture [`RecommendationData`](crate::types::RecommendationData).
    pub fn builder() -> crate::types::builders::RecommendationDataBuilder {
        crate::types::builders::RecommendationDataBuilder::default()
    }
}

/// A builder for [`RecommendationData`](crate::types::RecommendationData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendationDataBuilder {
    pub(crate) recommendation_id: ::std::option::Option<::std::string::String>,
    pub(crate) document: ::std::option::Option<crate::types::Document>,
    pub(crate) relevance_score: ::std::option::Option<f64>,
    pub(crate) relevance_level: ::std::option::Option<crate::types::RelevanceLevel>,
    pub(crate) r#type: ::std::option::Option<crate::types::RecommendationType>,
    pub(crate) data: ::std::option::Option<crate::types::DataSummary>,
}
impl RecommendationDataBuilder {
    /// <p>The identifier of the recommendation.</p>
    /// This field is required.
    pub fn recommendation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.recommendation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the recommendation.</p>
    pub fn set_recommendation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.recommendation_id = input;
        self
    }
    /// <p>The identifier of the recommendation.</p>
    pub fn get_recommendation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.recommendation_id
    }
    /// <p>The recommended document.</p>
    pub fn document(mut self, input: crate::types::Document) -> Self {
        self.document = ::std::option::Option::Some(input);
        self
    }
    /// <p>The recommended document.</p>
    pub fn set_document(mut self, input: ::std::option::Option<crate::types::Document>) -> Self {
        self.document = input;
        self
    }
    /// <p>The recommended document.</p>
    pub fn get_document(&self) -> &::std::option::Option<crate::types::Document> {
        &self.document
    }
    /// <p>The relevance score of the recommendation.</p>
    pub fn relevance_score(mut self, input: f64) -> Self {
        self.relevance_score = ::std::option::Option::Some(input);
        self
    }
    /// <p>The relevance score of the recommendation.</p>
    pub fn set_relevance_score(mut self, input: ::std::option::Option<f64>) -> Self {
        self.relevance_score = input;
        self
    }
    /// <p>The relevance score of the recommendation.</p>
    pub fn get_relevance_score(&self) -> &::std::option::Option<f64> {
        &self.relevance_score
    }
    /// <p>The relevance level of the recommendation.</p>
    pub fn relevance_level(mut self, input: crate::types::RelevanceLevel) -> Self {
        self.relevance_level = ::std::option::Option::Some(input);
        self
    }
    /// <p>The relevance level of the recommendation.</p>
    pub fn set_relevance_level(mut self, input: ::std::option::Option<crate::types::RelevanceLevel>) -> Self {
        self.relevance_level = input;
        self
    }
    /// <p>The relevance level of the recommendation.</p>
    pub fn get_relevance_level(&self) -> &::std::option::Option<crate::types::RelevanceLevel> {
        &self.relevance_level
    }
    /// <p>The type of recommendation.</p>
    pub fn r#type(mut self, input: crate::types::RecommendationType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of recommendation.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RecommendationType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of recommendation.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RecommendationType> {
        &self.r#type
    }
    /// <p>Summary of the recommended content.</p>
    pub fn data(mut self, input: crate::types::DataSummary) -> Self {
        self.data = ::std::option::Option::Some(input);
        self
    }
    /// <p>Summary of the recommended content.</p>
    pub fn set_data(mut self, input: ::std::option::Option<crate::types::DataSummary>) -> Self {
        self.data = input;
        self
    }
    /// <p>Summary of the recommended content.</p>
    pub fn get_data(&self) -> &::std::option::Option<crate::types::DataSummary> {
        &self.data
    }
    /// Consumes the builder and constructs a [`RecommendationData`](crate::types::RecommendationData).
    /// This method will fail if any of the following fields are not set:
    /// - [`recommendation_id`](crate::types::builders::RecommendationDataBuilder::recommendation_id)
    pub fn build(self) -> ::std::result::Result<crate::types::RecommendationData, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RecommendationData {
            recommendation_id: self.recommendation_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "recommendation_id",
                    "recommendation_id was not specified but it is required when building RecommendationData",
                )
            })?,
            document: self.document,
            relevance_score: self.relevance_score.unwrap_or_default(),
            relevance_level: self.relevance_level,
            r#type: self.r#type,
            data: self.data,
        })
    }
}
