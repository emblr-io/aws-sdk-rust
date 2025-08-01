// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of rightsizing recommendations, including de-duped savings from all types of recommendations.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RecommendationSummary {
    /// <p>The grouping of recommendations.</p>
    pub group: ::std::option::Option<::std::string::String>,
    /// <p>The estimated total savings resulting from modifications, on a monthly basis.</p>
    pub estimated_monthly_savings: ::std::option::Option<f64>,
    /// <p>The total number of instance recommendations.</p>
    pub recommendation_count: ::std::option::Option<i32>,
}
impl RecommendationSummary {
    /// <p>The grouping of recommendations.</p>
    pub fn group(&self) -> ::std::option::Option<&str> {
        self.group.as_deref()
    }
    /// <p>The estimated total savings resulting from modifications, on a monthly basis.</p>
    pub fn estimated_monthly_savings(&self) -> ::std::option::Option<f64> {
        self.estimated_monthly_savings
    }
    /// <p>The total number of instance recommendations.</p>
    pub fn recommendation_count(&self) -> ::std::option::Option<i32> {
        self.recommendation_count
    }
}
impl RecommendationSummary {
    /// Creates a new builder-style object to manufacture [`RecommendationSummary`](crate::types::RecommendationSummary).
    pub fn builder() -> crate::types::builders::RecommendationSummaryBuilder {
        crate::types::builders::RecommendationSummaryBuilder::default()
    }
}

/// A builder for [`RecommendationSummary`](crate::types::RecommendationSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RecommendationSummaryBuilder {
    pub(crate) group: ::std::option::Option<::std::string::String>,
    pub(crate) estimated_monthly_savings: ::std::option::Option<f64>,
    pub(crate) recommendation_count: ::std::option::Option<i32>,
}
impl RecommendationSummaryBuilder {
    /// <p>The grouping of recommendations.</p>
    pub fn group(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.group = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The grouping of recommendations.</p>
    pub fn set_group(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.group = input;
        self
    }
    /// <p>The grouping of recommendations.</p>
    pub fn get_group(&self) -> &::std::option::Option<::std::string::String> {
        &self.group
    }
    /// <p>The estimated total savings resulting from modifications, on a monthly basis.</p>
    pub fn estimated_monthly_savings(mut self, input: f64) -> Self {
        self.estimated_monthly_savings = ::std::option::Option::Some(input);
        self
    }
    /// <p>The estimated total savings resulting from modifications, on a monthly basis.</p>
    pub fn set_estimated_monthly_savings(mut self, input: ::std::option::Option<f64>) -> Self {
        self.estimated_monthly_savings = input;
        self
    }
    /// <p>The estimated total savings resulting from modifications, on a monthly basis.</p>
    pub fn get_estimated_monthly_savings(&self) -> &::std::option::Option<f64> {
        &self.estimated_monthly_savings
    }
    /// <p>The total number of instance recommendations.</p>
    pub fn recommendation_count(mut self, input: i32) -> Self {
        self.recommendation_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The total number of instance recommendations.</p>
    pub fn set_recommendation_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.recommendation_count = input;
        self
    }
    /// <p>The total number of instance recommendations.</p>
    pub fn get_recommendation_count(&self) -> &::std::option::Option<i32> {
        &self.recommendation_count
    }
    /// Consumes the builder and constructs a [`RecommendationSummary`](crate::types::RecommendationSummary).
    pub fn build(self) -> crate::types::RecommendationSummary {
        crate::types::RecommendationSummary {
            group: self.group,
            estimated_monthly_savings: self.estimated_monthly_savings,
            recommendation_count: self.recommendation_count,
        }
    }
}
