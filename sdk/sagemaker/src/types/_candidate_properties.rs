// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The properties of an AutoML candidate job.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CandidateProperties {
    /// <p>The Amazon S3 prefix to the artifacts generated for an AutoML candidate.</p>
    pub candidate_artifact_locations: ::std::option::Option<crate::types::CandidateArtifactLocations>,
    /// <p>Information about the candidate metrics for an AutoML job.</p>
    pub candidate_metrics: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>>,
}
impl CandidateProperties {
    /// <p>The Amazon S3 prefix to the artifacts generated for an AutoML candidate.</p>
    pub fn candidate_artifact_locations(&self) -> ::std::option::Option<&crate::types::CandidateArtifactLocations> {
        self.candidate_artifact_locations.as_ref()
    }
    /// <p>Information about the candidate metrics for an AutoML job.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.candidate_metrics.is_none()`.
    pub fn candidate_metrics(&self) -> &[crate::types::MetricDatum] {
        self.candidate_metrics.as_deref().unwrap_or_default()
    }
}
impl CandidateProperties {
    /// Creates a new builder-style object to manufacture [`CandidateProperties`](crate::types::CandidateProperties).
    pub fn builder() -> crate::types::builders::CandidatePropertiesBuilder {
        crate::types::builders::CandidatePropertiesBuilder::default()
    }
}

/// A builder for [`CandidateProperties`](crate::types::CandidateProperties).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CandidatePropertiesBuilder {
    pub(crate) candidate_artifact_locations: ::std::option::Option<crate::types::CandidateArtifactLocations>,
    pub(crate) candidate_metrics: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>>,
}
impl CandidatePropertiesBuilder {
    /// <p>The Amazon S3 prefix to the artifacts generated for an AutoML candidate.</p>
    pub fn candidate_artifact_locations(mut self, input: crate::types::CandidateArtifactLocations) -> Self {
        self.candidate_artifact_locations = ::std::option::Option::Some(input);
        self
    }
    /// <p>The Amazon S3 prefix to the artifacts generated for an AutoML candidate.</p>
    pub fn set_candidate_artifact_locations(mut self, input: ::std::option::Option<crate::types::CandidateArtifactLocations>) -> Self {
        self.candidate_artifact_locations = input;
        self
    }
    /// <p>The Amazon S3 prefix to the artifacts generated for an AutoML candidate.</p>
    pub fn get_candidate_artifact_locations(&self) -> &::std::option::Option<crate::types::CandidateArtifactLocations> {
        &self.candidate_artifact_locations
    }
    /// Appends an item to `candidate_metrics`.
    ///
    /// To override the contents of this collection use [`set_candidate_metrics`](Self::set_candidate_metrics).
    ///
    /// <p>Information about the candidate metrics for an AutoML job.</p>
    pub fn candidate_metrics(mut self, input: crate::types::MetricDatum) -> Self {
        let mut v = self.candidate_metrics.unwrap_or_default();
        v.push(input);
        self.candidate_metrics = ::std::option::Option::Some(v);
        self
    }
    /// <p>Information about the candidate metrics for an AutoML job.</p>
    pub fn set_candidate_metrics(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>>) -> Self {
        self.candidate_metrics = input;
        self
    }
    /// <p>Information about the candidate metrics for an AutoML job.</p>
    pub fn get_candidate_metrics(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::MetricDatum>> {
        &self.candidate_metrics
    }
    /// Consumes the builder and constructs a [`CandidateProperties`](crate::types::CandidateProperties).
    pub fn build(self) -> crate::types::CandidateProperties {
        crate::types::CandidateProperties {
            candidate_artifact_locations: self.candidate_artifact_locations,
            candidate_metrics: self.candidate_metrics,
        }
    }
}
