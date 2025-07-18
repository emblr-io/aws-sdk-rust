// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInsightsByAssessmentOutput {
    /// <p>The assessment analytics data that the <code>GetInsightsByAssessment</code> API returned.</p>
    pub insights: ::std::option::Option<crate::types::InsightsByAssessment>,
    _request_id: Option<String>,
}
impl GetInsightsByAssessmentOutput {
    /// <p>The assessment analytics data that the <code>GetInsightsByAssessment</code> API returned.</p>
    pub fn insights(&self) -> ::std::option::Option<&crate::types::InsightsByAssessment> {
        self.insights.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetInsightsByAssessmentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetInsightsByAssessmentOutput {
    /// Creates a new builder-style object to manufacture [`GetInsightsByAssessmentOutput`](crate::operation::get_insights_by_assessment::GetInsightsByAssessmentOutput).
    pub fn builder() -> crate::operation::get_insights_by_assessment::builders::GetInsightsByAssessmentOutputBuilder {
        crate::operation::get_insights_by_assessment::builders::GetInsightsByAssessmentOutputBuilder::default()
    }
}

/// A builder for [`GetInsightsByAssessmentOutput`](crate::operation::get_insights_by_assessment::GetInsightsByAssessmentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInsightsByAssessmentOutputBuilder {
    pub(crate) insights: ::std::option::Option<crate::types::InsightsByAssessment>,
    _request_id: Option<String>,
}
impl GetInsightsByAssessmentOutputBuilder {
    /// <p>The assessment analytics data that the <code>GetInsightsByAssessment</code> API returned.</p>
    pub fn insights(mut self, input: crate::types::InsightsByAssessment) -> Self {
        self.insights = ::std::option::Option::Some(input);
        self
    }
    /// <p>The assessment analytics data that the <code>GetInsightsByAssessment</code> API returned.</p>
    pub fn set_insights(mut self, input: ::std::option::Option<crate::types::InsightsByAssessment>) -> Self {
        self.insights = input;
        self
    }
    /// <p>The assessment analytics data that the <code>GetInsightsByAssessment</code> API returned.</p>
    pub fn get_insights(&self) -> &::std::option::Option<crate::types::InsightsByAssessment> {
        &self.insights
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetInsightsByAssessmentOutput`](crate::operation::get_insights_by_assessment::GetInsightsByAssessmentOutput).
    pub fn build(self) -> crate::operation::get_insights_by_assessment::GetInsightsByAssessmentOutput {
        crate::operation::get_insights_by_assessment::GetInsightsByAssessmentOutput {
            insights: self.insights,
            _request_id: self._request_id,
        }
    }
}
