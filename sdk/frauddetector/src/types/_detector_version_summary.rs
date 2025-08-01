// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>The summary of the detector version.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DetectorVersionSummary {
    /// <p>The detector version ID.</p>
    pub detector_version_id: ::std::option::Option<::std::string::String>,
    /// <p>The detector version status.</p>
    pub status: ::std::option::Option<crate::types::DetectorVersionStatus>,
    /// <p>The detector version description.</p>
    pub description: ::std::option::Option<::std::string::String>,
    /// <p>Timestamp of when the detector version was last updated.</p>
    pub last_updated_time: ::std::option::Option<::std::string::String>,
}
impl DetectorVersionSummary {
    /// <p>The detector version ID.</p>
    pub fn detector_version_id(&self) -> ::std::option::Option<&str> {
        self.detector_version_id.as_deref()
    }
    /// <p>The detector version status.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::DetectorVersionStatus> {
        self.status.as_ref()
    }
    /// <p>The detector version description.</p>
    pub fn description(&self) -> ::std::option::Option<&str> {
        self.description.as_deref()
    }
    /// <p>Timestamp of when the detector version was last updated.</p>
    pub fn last_updated_time(&self) -> ::std::option::Option<&str> {
        self.last_updated_time.as_deref()
    }
}
impl DetectorVersionSummary {
    /// Creates a new builder-style object to manufacture [`DetectorVersionSummary`](crate::types::DetectorVersionSummary).
    pub fn builder() -> crate::types::builders::DetectorVersionSummaryBuilder {
        crate::types::builders::DetectorVersionSummaryBuilder::default()
    }
}

/// A builder for [`DetectorVersionSummary`](crate::types::DetectorVersionSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DetectorVersionSummaryBuilder {
    pub(crate) detector_version_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<crate::types::DetectorVersionStatus>,
    pub(crate) description: ::std::option::Option<::std::string::String>,
    pub(crate) last_updated_time: ::std::option::Option<::std::string::String>,
}
impl DetectorVersionSummaryBuilder {
    /// <p>The detector version ID.</p>
    pub fn detector_version_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detector_version_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The detector version ID.</p>
    pub fn set_detector_version_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detector_version_id = input;
        self
    }
    /// <p>The detector version ID.</p>
    pub fn get_detector_version_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.detector_version_id
    }
    /// <p>The detector version status.</p>
    pub fn status(mut self, input: crate::types::DetectorVersionStatus) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The detector version status.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::DetectorVersionStatus>) -> Self {
        self.status = input;
        self
    }
    /// <p>The detector version status.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::DetectorVersionStatus> {
        &self.status
    }
    /// <p>The detector version description.</p>
    pub fn description(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.description = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The detector version description.</p>
    pub fn set_description(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.description = input;
        self
    }
    /// <p>The detector version description.</p>
    pub fn get_description(&self) -> &::std::option::Option<::std::string::String> {
        &self.description
    }
    /// <p>Timestamp of when the detector version was last updated.</p>
    pub fn last_updated_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.last_updated_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Timestamp of when the detector version was last updated.</p>
    pub fn set_last_updated_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.last_updated_time = input;
        self
    }
    /// <p>Timestamp of when the detector version was last updated.</p>
    pub fn get_last_updated_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.last_updated_time
    }
    /// Consumes the builder and constructs a [`DetectorVersionSummary`](crate::types::DetectorVersionSummary).
    pub fn build(self) -> crate::types::DetectorVersionSummary {
        crate::types::DetectorVersionSummary {
            detector_version_id: self.detector_version_id,
            status: self.status,
            description: self.description,
            last_updated_time: self.last_updated_time,
        }
    }
}
