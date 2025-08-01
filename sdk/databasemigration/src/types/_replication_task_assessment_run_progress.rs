// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The progress values reported by the <code>AssessmentProgress</code> response element.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ReplicationTaskAssessmentRunProgress {
    /// <p>The number of individual assessments that are specified to run.</p>
    pub individual_assessment_count: i32,
    /// <p>The number of individual assessments that have completed, successfully or not.</p>
    pub individual_assessment_completed_count: i32,
}
impl ReplicationTaskAssessmentRunProgress {
    /// <p>The number of individual assessments that are specified to run.</p>
    pub fn individual_assessment_count(&self) -> i32 {
        self.individual_assessment_count
    }
    /// <p>The number of individual assessments that have completed, successfully or not.</p>
    pub fn individual_assessment_completed_count(&self) -> i32 {
        self.individual_assessment_completed_count
    }
}
impl ReplicationTaskAssessmentRunProgress {
    /// Creates a new builder-style object to manufacture [`ReplicationTaskAssessmentRunProgress`](crate::types::ReplicationTaskAssessmentRunProgress).
    pub fn builder() -> crate::types::builders::ReplicationTaskAssessmentRunProgressBuilder {
        crate::types::builders::ReplicationTaskAssessmentRunProgressBuilder::default()
    }
}

/// A builder for [`ReplicationTaskAssessmentRunProgress`](crate::types::ReplicationTaskAssessmentRunProgress).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ReplicationTaskAssessmentRunProgressBuilder {
    pub(crate) individual_assessment_count: ::std::option::Option<i32>,
    pub(crate) individual_assessment_completed_count: ::std::option::Option<i32>,
}
impl ReplicationTaskAssessmentRunProgressBuilder {
    /// <p>The number of individual assessments that are specified to run.</p>
    pub fn individual_assessment_count(mut self, input: i32) -> Self {
        self.individual_assessment_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of individual assessments that are specified to run.</p>
    pub fn set_individual_assessment_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.individual_assessment_count = input;
        self
    }
    /// <p>The number of individual assessments that are specified to run.</p>
    pub fn get_individual_assessment_count(&self) -> &::std::option::Option<i32> {
        &self.individual_assessment_count
    }
    /// <p>The number of individual assessments that have completed, successfully or not.</p>
    pub fn individual_assessment_completed_count(mut self, input: i32) -> Self {
        self.individual_assessment_completed_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>The number of individual assessments that have completed, successfully or not.</p>
    pub fn set_individual_assessment_completed_count(mut self, input: ::std::option::Option<i32>) -> Self {
        self.individual_assessment_completed_count = input;
        self
    }
    /// <p>The number of individual assessments that have completed, successfully or not.</p>
    pub fn get_individual_assessment_completed_count(&self) -> &::std::option::Option<i32> {
        &self.individual_assessment_completed_count
    }
    /// Consumes the builder and constructs a [`ReplicationTaskAssessmentRunProgress`](crate::types::ReplicationTaskAssessmentRunProgress).
    pub fn build(self) -> crate::types::ReplicationTaskAssessmentRunProgress {
        crate::types::ReplicationTaskAssessmentRunProgress {
            individual_assessment_count: self.individual_assessment_count.unwrap_or_default(),
            individual_assessment_completed_count: self.individual_assessment_completed_count.unwrap_or_default(),
        }
    }
}
