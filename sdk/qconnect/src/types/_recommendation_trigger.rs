// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A recommendation trigger provides context on the event that produced the referenced recommendations. Recommendations are only referenced in <code>recommendationIds</code> by a single RecommendationTrigger.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecommendationTrigger {
    /// <p>The identifier of the recommendation trigger.</p>
    pub id: ::std::string::String,
    /// <p>The type of recommendation trigger.</p>
    pub r#type: crate::types::RecommendationTriggerType,
    /// <p>The source of the recommendation trigger.</p>
    /// <ul>
    /// <li>
    /// <p>ISSUE_DETECTION: The corresponding recommendations were triggered by a Contact Lens issue.</p></li>
    /// <li>
    /// <p>RULE_EVALUATION: The corresponding recommendations were triggered by a Contact Lens rule.</p></li>
    /// </ul>
    pub source: crate::types::RecommendationSourceType,
    /// <p>A union type containing information related to the trigger.</p>
    pub data: ::std::option::Option<crate::types::RecommendationTriggerData>,
    /// <p>The identifiers of the recommendations.</p>
    pub recommendation_ids: ::std::vec::Vec<::std::string::String>,
}
impl RecommendationTrigger {
    /// <p>The identifier of the recommendation trigger.</p>
    pub fn id(&self) -> &str {
        use std::ops::Deref;
        self.id.deref()
    }
    /// <p>The type of recommendation trigger.</p>
    pub fn r#type(&self) -> &crate::types::RecommendationTriggerType {
        &self.r#type
    }
    /// <p>The source of the recommendation trigger.</p>
    /// <ul>
    /// <li>
    /// <p>ISSUE_DETECTION: The corresponding recommendations were triggered by a Contact Lens issue.</p></li>
    /// <li>
    /// <p>RULE_EVALUATION: The corresponding recommendations were triggered by a Contact Lens rule.</p></li>
    /// </ul>
    pub fn source(&self) -> &crate::types::RecommendationSourceType {
        &self.source
    }
    /// <p>A union type containing information related to the trigger.</p>
    pub fn data(&self) -> ::std::option::Option<&crate::types::RecommendationTriggerData> {
        self.data.as_ref()
    }
    /// <p>The identifiers of the recommendations.</p>
    pub fn recommendation_ids(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.recommendation_ids.deref()
    }
}
impl RecommendationTrigger {
    /// Creates a new builder-style object to manufacture [`RecommendationTrigger`](crate::types::RecommendationTrigger).
    pub fn builder() -> crate::types::builders::RecommendationTriggerBuilder {
        crate::types::builders::RecommendationTriggerBuilder::default()
    }
}

/// A builder for [`RecommendationTrigger`](crate::types::RecommendationTrigger).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendationTriggerBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) r#type: ::std::option::Option<crate::types::RecommendationTriggerType>,
    pub(crate) source: ::std::option::Option<crate::types::RecommendationSourceType>,
    pub(crate) data: ::std::option::Option<crate::types::RecommendationTriggerData>,
    pub(crate) recommendation_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RecommendationTriggerBuilder {
    /// <p>The identifier of the recommendation trigger.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the recommendation trigger.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The identifier of the recommendation trigger.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The type of recommendation trigger.</p>
    /// This field is required.
    pub fn r#type(mut self, input: crate::types::RecommendationTriggerType) -> Self {
        self.r#type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of recommendation trigger.</p>
    pub fn set_type(mut self, input: ::std::option::Option<crate::types::RecommendationTriggerType>) -> Self {
        self.r#type = input;
        self
    }
    /// <p>The type of recommendation trigger.</p>
    pub fn get_type(&self) -> &::std::option::Option<crate::types::RecommendationTriggerType> {
        &self.r#type
    }
    /// <p>The source of the recommendation trigger.</p>
    /// <ul>
    /// <li>
    /// <p>ISSUE_DETECTION: The corresponding recommendations were triggered by a Contact Lens issue.</p></li>
    /// <li>
    /// <p>RULE_EVALUATION: The corresponding recommendations were triggered by a Contact Lens rule.</p></li>
    /// </ul>
    /// This field is required.
    pub fn source(mut self, input: crate::types::RecommendationSourceType) -> Self {
        self.source = ::std::option::Option::Some(input);
        self
    }
    /// <p>The source of the recommendation trigger.</p>
    /// <ul>
    /// <li>
    /// <p>ISSUE_DETECTION: The corresponding recommendations were triggered by a Contact Lens issue.</p></li>
    /// <li>
    /// <p>RULE_EVALUATION: The corresponding recommendations were triggered by a Contact Lens rule.</p></li>
    /// </ul>
    pub fn set_source(mut self, input: ::std::option::Option<crate::types::RecommendationSourceType>) -> Self {
        self.source = input;
        self
    }
    /// <p>The source of the recommendation trigger.</p>
    /// <ul>
    /// <li>
    /// <p>ISSUE_DETECTION: The corresponding recommendations were triggered by a Contact Lens issue.</p></li>
    /// <li>
    /// <p>RULE_EVALUATION: The corresponding recommendations were triggered by a Contact Lens rule.</p></li>
    /// </ul>
    pub fn get_source(&self) -> &::std::option::Option<crate::types::RecommendationSourceType> {
        &self.source
    }
    /// <p>A union type containing information related to the trigger.</p>
    /// This field is required.
    pub fn data(mut self, input: crate::types::RecommendationTriggerData) -> Self {
        self.data = ::std::option::Option::Some(input);
        self
    }
    /// <p>A union type containing information related to the trigger.</p>
    pub fn set_data(mut self, input: ::std::option::Option<crate::types::RecommendationTriggerData>) -> Self {
        self.data = input;
        self
    }
    /// <p>A union type containing information related to the trigger.</p>
    pub fn get_data(&self) -> &::std::option::Option<crate::types::RecommendationTriggerData> {
        &self.data
    }
    /// Appends an item to `recommendation_ids`.
    ///
    /// To override the contents of this collection use [`set_recommendation_ids`](Self::set_recommendation_ids).
    ///
    /// <p>The identifiers of the recommendations.</p>
    pub fn recommendation_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.recommendation_ids.unwrap_or_default();
        v.push(input.into());
        self.recommendation_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The identifiers of the recommendations.</p>
    pub fn set_recommendation_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.recommendation_ids = input;
        self
    }
    /// <p>The identifiers of the recommendations.</p>
    pub fn get_recommendation_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.recommendation_ids
    }
    /// Consumes the builder and constructs a [`RecommendationTrigger`](crate::types::RecommendationTrigger).
    /// This method will fail if any of the following fields are not set:
    /// - [`id`](crate::types::builders::RecommendationTriggerBuilder::id)
    /// - [`r#type`](crate::types::builders::RecommendationTriggerBuilder::type)
    /// - [`source`](crate::types::builders::RecommendationTriggerBuilder::source)
    /// - [`recommendation_ids`](crate::types::builders::RecommendationTriggerBuilder::recommendation_ids)
    pub fn build(self) -> ::std::result::Result<crate::types::RecommendationTrigger, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RecommendationTrigger {
            id: self.id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "id",
                    "id was not specified but it is required when building RecommendationTrigger",
                )
            })?,
            r#type: self.r#type.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "r#type",
                    "r#type was not specified but it is required when building RecommendationTrigger",
                )
            })?,
            source: self.source.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "source",
                    "source was not specified but it is required when building RecommendationTrigger",
                )
            })?,
            data: self.data,
            recommendation_ids: self.recommendation_ids.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "recommendation_ids",
                    "recommendation_ids was not specified but it is required when building RecommendationTrigger",
                )
            })?,
        })
    }
}
