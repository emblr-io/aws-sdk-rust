// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Segment type containing a list of detected issues.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RealTimeContactAnalysisSegmentIssues {
    /// <p>List of the issues detected.</p>
    pub issues_detected: ::std::vec::Vec<crate::types::RealTimeContactAnalysisIssueDetected>,
}
impl RealTimeContactAnalysisSegmentIssues {
    /// <p>List of the issues detected.</p>
    pub fn issues_detected(&self) -> &[crate::types::RealTimeContactAnalysisIssueDetected] {
        use std::ops::Deref;
        self.issues_detected.deref()
    }
}
impl RealTimeContactAnalysisSegmentIssues {
    /// Creates a new builder-style object to manufacture [`RealTimeContactAnalysisSegmentIssues`](crate::types::RealTimeContactAnalysisSegmentIssues).
    pub fn builder() -> crate::types::builders::RealTimeContactAnalysisSegmentIssuesBuilder {
        crate::types::builders::RealTimeContactAnalysisSegmentIssuesBuilder::default()
    }
}

/// A builder for [`RealTimeContactAnalysisSegmentIssues`](crate::types::RealTimeContactAnalysisSegmentIssues).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RealTimeContactAnalysisSegmentIssuesBuilder {
    pub(crate) issues_detected: ::std::option::Option<::std::vec::Vec<crate::types::RealTimeContactAnalysisIssueDetected>>,
}
impl RealTimeContactAnalysisSegmentIssuesBuilder {
    /// Appends an item to `issues_detected`.
    ///
    /// To override the contents of this collection use [`set_issues_detected`](Self::set_issues_detected).
    ///
    /// <p>List of the issues detected.</p>
    pub fn issues_detected(mut self, input: crate::types::RealTimeContactAnalysisIssueDetected) -> Self {
        let mut v = self.issues_detected.unwrap_or_default();
        v.push(input);
        self.issues_detected = ::std::option::Option::Some(v);
        self
    }
    /// <p>List of the issues detected.</p>
    pub fn set_issues_detected(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::RealTimeContactAnalysisIssueDetected>>) -> Self {
        self.issues_detected = input;
        self
    }
    /// <p>List of the issues detected.</p>
    pub fn get_issues_detected(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::RealTimeContactAnalysisIssueDetected>> {
        &self.issues_detected
    }
    /// Consumes the builder and constructs a [`RealTimeContactAnalysisSegmentIssues`](crate::types::RealTimeContactAnalysisSegmentIssues).
    /// This method will fail if any of the following fields are not set:
    /// - [`issues_detected`](crate::types::builders::RealTimeContactAnalysisSegmentIssuesBuilder::issues_detected)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::types::RealTimeContactAnalysisSegmentIssues, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RealTimeContactAnalysisSegmentIssues {
            issues_detected: self.issues_detected.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "issues_detected",
                    "issues_detected was not specified but it is required when building RealTimeContactAnalysisSegmentIssues",
                )
            })?,
        })
    }
}
