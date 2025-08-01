// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>A summary of the latest analytics data for a specific control in a specific active assessment.</p>
/// <p>Control insights are grouped by control domain, and ranked by the highest total count of non-compliant evidence.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ControlInsightsMetadataByAssessmentItem {
    /// <p>The name of the assessment control.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier for the assessment control.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>A breakdown of the compliance check status for the evidence that’s associated with the assessment control.</p>
    pub evidence_insights: ::std::option::Option<crate::types::EvidenceInsights>,
    /// <p>The name of the control set that the assessment control belongs to.</p>
    pub control_set_name: ::std::option::Option<::std::string::String>,
    /// <p>The time when the assessment control insights were last updated.</p>
    pub last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ControlInsightsMetadataByAssessmentItem {
    /// <p>The name of the assessment control.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>The unique identifier for the assessment control.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>A breakdown of the compliance check status for the evidence that’s associated with the assessment control.</p>
    pub fn evidence_insights(&self) -> ::std::option::Option<&crate::types::EvidenceInsights> {
        self.evidence_insights.as_ref()
    }
    /// <p>The name of the control set that the assessment control belongs to.</p>
    pub fn control_set_name(&self) -> ::std::option::Option<&str> {
        self.control_set_name.as_deref()
    }
    /// <p>The time when the assessment control insights were last updated.</p>
    pub fn last_updated(&self) -> ::std::option::Option<&::aws_smithy_types::DateTime> {
        self.last_updated.as_ref()
    }
}
impl ControlInsightsMetadataByAssessmentItem {
    /// Creates a new builder-style object to manufacture [`ControlInsightsMetadataByAssessmentItem`](crate::types::ControlInsightsMetadataByAssessmentItem).
    pub fn builder() -> crate::types::builders::ControlInsightsMetadataByAssessmentItemBuilder {
        crate::types::builders::ControlInsightsMetadataByAssessmentItemBuilder::default()
    }
}

/// A builder for [`ControlInsightsMetadataByAssessmentItem`](crate::types::ControlInsightsMetadataByAssessmentItem).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ControlInsightsMetadataByAssessmentItemBuilder {
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) evidence_insights: ::std::option::Option<crate::types::EvidenceInsights>,
    pub(crate) control_set_name: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated: ::std::option::Option<::aws_smithy_types::DateTime>,
}
impl ControlInsightsMetadataByAssessmentItemBuilder {
    /// <p>The name of the assessment control.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the assessment control.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>The name of the assessment control.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// <p>The unique identifier for the assessment control.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier for the assessment control.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique identifier for the assessment control.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>A breakdown of the compliance check status for the evidence that’s associated with the assessment control.</p>
    pub fn evidence_insights(mut self, input: crate::types::EvidenceInsights) -> Self {
        self.evidence_insights = ::std::option::Option::Some(input);
        self
    }
    /// <p>A breakdown of the compliance check status for the evidence that’s associated with the assessment control.</p>
    pub fn set_evidence_insights(mut self, input: ::std::option::Option<crate::types::EvidenceInsights>) -> Self {
        self.evidence_insights = input;
        self
    }
    /// <p>A breakdown of the compliance check status for the evidence that’s associated with the assessment control.</p>
    pub fn get_evidence_insights(&self) -> &::std::option::Option<crate::types::EvidenceInsights> {
        &self.evidence_insights
    }
    /// <p>The name of the control set that the assessment control belongs to.</p>
    pub fn control_set_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_set_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the control set that the assessment control belongs to.</p>
    pub fn set_control_set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_set_name = input;
        self
    }
    /// <p>The name of the control set that the assessment control belongs to.</p>
    pub fn get_control_set_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_set_name
    }
    /// <p>The time when the assessment control insights were last updated.</p>
    pub fn last_updated(mut self, input: ::aws_smithy_types::DateTime) -> Self {
        self.last_updated = ::std::option::Option::Some(input);
        self
    }
    /// <p>The time when the assessment control insights were last updated.</p>
    pub fn set_last_updated(mut self, input: ::std::option::Option<::aws_smithy_types::DateTime>) -> Self {
        self.last_updated = input;
        self
    }
    /// <p>The time when the assessment control insights were last updated.</p>
    pub fn get_last_updated(&self) -> &::std::option::Option<::aws_smithy_types::DateTime> {
        &self.last_updated
    }
    /// Consumes the builder and constructs a [`ControlInsightsMetadataByAssessmentItem`](crate::types::ControlInsightsMetadataByAssessmentItem).
    pub fn build(self) -> crate::types::ControlInsightsMetadataByAssessmentItem {
        crate::types::ControlInsightsMetadataByAssessmentItem {
            name: self.name,
            id: self.id,
            evidence_insights: self.evidence_insights,
            control_set_name: self.control_set_name,
            last_updated: self.last_updated,
        }
    }
}
