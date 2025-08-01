// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Reference data used to evaluate Performance Insights to determine if its performance is anomalous or not.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct PerformanceInsightsReferenceData {
    /// <p>The name of the reference data.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The specific reference values used to evaluate the Performance Insights. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceComparisonValues.html">PerformanceInsightsReferenceComparisonValues</a> </code>.</p>
    pub comparison_values: ::std::option::Option<crate::types::PerformanceInsightsReferenceComparisonValues>,
}
impl PerformanceInsightsReferenceData {
    /// <p>The name of the reference data.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The specific reference values used to evaluate the Performance Insights. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceComparisonValues.html">PerformanceInsightsReferenceComparisonValues</a> </code>.</p>
    pub fn comparison_values(&self) -> ::std::option::Option<&crate::types::PerformanceInsightsReferenceComparisonValues> {
        self.comparison_values.as_ref()
    }
}
impl PerformanceInsightsReferenceData {
    /// Creates a new builder-style object to manufacture [`PerformanceInsightsReferenceData`](crate::types::PerformanceInsightsReferenceData).
    pub fn builder() -> crate::types::builders::PerformanceInsightsReferenceDataBuilder {
        crate::types::builders::PerformanceInsightsReferenceDataBuilder::default()
    }
}

/// A builder for [`PerformanceInsightsReferenceData`](crate::types::PerformanceInsightsReferenceData).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct PerformanceInsightsReferenceDataBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) comparison_values: ::std::option::Option<crate::types::PerformanceInsightsReferenceComparisonValues>,
}
impl PerformanceInsightsReferenceDataBuilder {
    /// <p>The name of the reference data.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the reference data.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the reference data.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The specific reference values used to evaluate the Performance Insights. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceComparisonValues.html">PerformanceInsightsReferenceComparisonValues</a> </code>.</p>
    pub fn comparison_values(mut self, input: crate::types::PerformanceInsightsReferenceComparisonValues) -> Self {
        self.comparison_values = ::std::option::Option::Some(input);
        self
    }
    /// <p>The specific reference values used to evaluate the Performance Insights. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceComparisonValues.html">PerformanceInsightsReferenceComparisonValues</a> </code>.</p>
    pub fn set_comparison_values(mut self, input: ::std::option::Option<crate::types::PerformanceInsightsReferenceComparisonValues>) -> Self {
        self.comparison_values = input;
        self
    }
    /// <p>The specific reference values used to evaluate the Performance Insights. For more information, see <code> <a href="https://docs.aws.amazon.com/devops-guru/latest/APIReference/API_PerformanceInsightsReferenceComparisonValues.html">PerformanceInsightsReferenceComparisonValues</a> </code>.</p>
    pub fn get_comparison_values(&self) -> &::std::option::Option<crate::types::PerformanceInsightsReferenceComparisonValues> {
        &self.comparison_values
    }
    /// Consumes the builder and constructs a [`PerformanceInsightsReferenceData`](crate::types::PerformanceInsightsReferenceData).
    pub fn build(self) -> crate::types::PerformanceInsightsReferenceData {
        crate::types::PerformanceInsightsReferenceData {
            name: self.name,
            comparison_values: self.comparison_values,
        }
    }
}
