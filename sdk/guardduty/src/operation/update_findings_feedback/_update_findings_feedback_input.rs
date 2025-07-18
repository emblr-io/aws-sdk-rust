// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct UpdateFindingsFeedbackInput {
    /// <p>The ID of the detector that is associated with the findings for which you want to update the feedback.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub detector_id: ::std::option::Option<::std::string::String>,
    /// <p>The IDs of the findings that you want to mark as useful or not useful.</p>
    pub finding_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>The feedback for the finding.</p>
    pub feedback: ::std::option::Option<crate::types::Feedback>,
    /// <p>Additional feedback about the GuardDuty findings.</p>
    pub comments: ::std::option::Option<::std::string::String>,
}
impl UpdateFindingsFeedbackInput {
    /// <p>The ID of the detector that is associated with the findings for which you want to update the feedback.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn detector_id(&self) -> ::std::option::Option<&str> {
        self.detector_id.as_deref()
    }
    /// <p>The IDs of the findings that you want to mark as useful or not useful.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.finding_ids.is_none()`.
    pub fn finding_ids(&self) -> &[::std::string::String] {
        self.finding_ids.as_deref().unwrap_or_default()
    }
    /// <p>The feedback for the finding.</p>
    pub fn feedback(&self) -> ::std::option::Option<&crate::types::Feedback> {
        self.feedback.as_ref()
    }
    /// <p>Additional feedback about the GuardDuty findings.</p>
    pub fn comments(&self) -> ::std::option::Option<&str> {
        self.comments.as_deref()
    }
}
impl UpdateFindingsFeedbackInput {
    /// Creates a new builder-style object to manufacture [`UpdateFindingsFeedbackInput`](crate::operation::update_findings_feedback::UpdateFindingsFeedbackInput).
    pub fn builder() -> crate::operation::update_findings_feedback::builders::UpdateFindingsFeedbackInputBuilder {
        crate::operation::update_findings_feedback::builders::UpdateFindingsFeedbackInputBuilder::default()
    }
}

/// A builder for [`UpdateFindingsFeedbackInput`](crate::operation::update_findings_feedback::UpdateFindingsFeedbackInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct UpdateFindingsFeedbackInputBuilder {
    pub(crate) detector_id: ::std::option::Option<::std::string::String>,
    pub(crate) finding_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) feedback: ::std::option::Option<crate::types::Feedback>,
    pub(crate) comments: ::std::option::Option<::std::string::String>,
}
impl UpdateFindingsFeedbackInputBuilder {
    /// <p>The ID of the detector that is associated with the findings for which you want to update the feedback.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    /// This field is required.
    pub fn detector_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detector_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the detector that is associated with the findings for which you want to update the feedback.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn set_detector_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detector_id = input;
        self
    }
    /// <p>The ID of the detector that is associated with the findings for which you want to update the feedback.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn get_detector_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.detector_id
    }
    /// Appends an item to `finding_ids`.
    ///
    /// To override the contents of this collection use [`set_finding_ids`](Self::set_finding_ids).
    ///
    /// <p>The IDs of the findings that you want to mark as useful or not useful.</p>
    pub fn finding_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.finding_ids.unwrap_or_default();
        v.push(input.into());
        self.finding_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>The IDs of the findings that you want to mark as useful or not useful.</p>
    pub fn set_finding_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.finding_ids = input;
        self
    }
    /// <p>The IDs of the findings that you want to mark as useful or not useful.</p>
    pub fn get_finding_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.finding_ids
    }
    /// <p>The feedback for the finding.</p>
    /// This field is required.
    pub fn feedback(mut self, input: crate::types::Feedback) -> Self {
        self.feedback = ::std::option::Option::Some(input);
        self
    }
    /// <p>The feedback for the finding.</p>
    pub fn set_feedback(mut self, input: ::std::option::Option<crate::types::Feedback>) -> Self {
        self.feedback = input;
        self
    }
    /// <p>The feedback for the finding.</p>
    pub fn get_feedback(&self) -> &::std::option::Option<crate::types::Feedback> {
        &self.feedback
    }
    /// <p>Additional feedback about the GuardDuty findings.</p>
    pub fn comments(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.comments = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Additional feedback about the GuardDuty findings.</p>
    pub fn set_comments(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.comments = input;
        self
    }
    /// <p>Additional feedback about the GuardDuty findings.</p>
    pub fn get_comments(&self) -> &::std::option::Option<::std::string::String> {
        &self.comments
    }
    /// Consumes the builder and constructs a [`UpdateFindingsFeedbackInput`](crate::operation::update_findings_feedback::UpdateFindingsFeedbackInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::update_findings_feedback::UpdateFindingsFeedbackInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::update_findings_feedback::UpdateFindingsFeedbackInput {
            detector_id: self.detector_id,
            finding_ids: self.finding_ids,
            feedback: self.feedback,
            comments: self.comments,
        })
    }
}
