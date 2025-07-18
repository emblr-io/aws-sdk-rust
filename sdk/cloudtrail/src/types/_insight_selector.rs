// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A JSON string that contains a list of Insights types that are logged on a trail or event data store.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InsightSelector {
    /// <p>The type of Insights events to log on a trail or event data store. <code>ApiCallRateInsight</code> and <code>ApiErrorRateInsight</code> are valid Insight types.</p>
    /// <p>The <code>ApiCallRateInsight</code> Insights type analyzes write-only management API calls that are aggregated per minute against a baseline API call volume.</p>
    /// <p>The <code>ApiErrorRateInsight</code> Insights type analyzes management API calls that result in error codes. The error is shown if the API call is unsuccessful.</p>
    pub insight_type: ::std::option::Option<crate::types::InsightType>,
}
impl InsightSelector {
    /// <p>The type of Insights events to log on a trail or event data store. <code>ApiCallRateInsight</code> and <code>ApiErrorRateInsight</code> are valid Insight types.</p>
    /// <p>The <code>ApiCallRateInsight</code> Insights type analyzes write-only management API calls that are aggregated per minute against a baseline API call volume.</p>
    /// <p>The <code>ApiErrorRateInsight</code> Insights type analyzes management API calls that result in error codes. The error is shown if the API call is unsuccessful.</p>
    pub fn insight_type(&self) -> ::std::option::Option<&crate::types::InsightType> {
        self.insight_type.as_ref()
    }
}
impl InsightSelector {
    /// Creates a new builder-style object to manufacture [`InsightSelector`](crate::types::InsightSelector).
    pub fn builder() -> crate::types::builders::InsightSelectorBuilder {
        crate::types::builders::InsightSelectorBuilder::default()
    }
}

/// A builder for [`InsightSelector`](crate::types::InsightSelector).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InsightSelectorBuilder {
    pub(crate) insight_type: ::std::option::Option<crate::types::InsightType>,
}
impl InsightSelectorBuilder {
    /// <p>The type of Insights events to log on a trail or event data store. <code>ApiCallRateInsight</code> and <code>ApiErrorRateInsight</code> are valid Insight types.</p>
    /// <p>The <code>ApiCallRateInsight</code> Insights type analyzes write-only management API calls that are aggregated per minute against a baseline API call volume.</p>
    /// <p>The <code>ApiErrorRateInsight</code> Insights type analyzes management API calls that result in error codes. The error is shown if the API call is unsuccessful.</p>
    pub fn insight_type(mut self, input: crate::types::InsightType) -> Self {
        self.insight_type = ::std::option::Option::Some(input);
        self
    }
    /// <p>The type of Insights events to log on a trail or event data store. <code>ApiCallRateInsight</code> and <code>ApiErrorRateInsight</code> are valid Insight types.</p>
    /// <p>The <code>ApiCallRateInsight</code> Insights type analyzes write-only management API calls that are aggregated per minute against a baseline API call volume.</p>
    /// <p>The <code>ApiErrorRateInsight</code> Insights type analyzes management API calls that result in error codes. The error is shown if the API call is unsuccessful.</p>
    pub fn set_insight_type(mut self, input: ::std::option::Option<crate::types::InsightType>) -> Self {
        self.insight_type = input;
        self
    }
    /// <p>The type of Insights events to log on a trail or event data store. <code>ApiCallRateInsight</code> and <code>ApiErrorRateInsight</code> are valid Insight types.</p>
    /// <p>The <code>ApiCallRateInsight</code> Insights type analyzes write-only management API calls that are aggregated per minute against a baseline API call volume.</p>
    /// <p>The <code>ApiErrorRateInsight</code> Insights type analyzes management API calls that result in error codes. The error is shown if the API call is unsuccessful.</p>
    pub fn get_insight_type(&self) -> &::std::option::Option<crate::types::InsightType> {
        &self.insight_type
    }
    /// Consumes the builder and constructs a [`InsightSelector`](crate::types::InsightSelector).
    pub fn build(self) -> crate::types::InsightSelector {
        crate::types::InsightSelector {
            insight_type: self.insight_type,
        }
    }
}
