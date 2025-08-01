// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the Amazon Inspector score given to a finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct InspectorScoreDetails {
    /// <p>An object that contains details about the CVSS score given to a finding.</p>
    pub adjusted_cvss: ::std::option::Option<crate::types::CvssScoreDetails>,
}
impl InspectorScoreDetails {
    /// <p>An object that contains details about the CVSS score given to a finding.</p>
    pub fn adjusted_cvss(&self) -> ::std::option::Option<&crate::types::CvssScoreDetails> {
        self.adjusted_cvss.as_ref()
    }
}
impl InspectorScoreDetails {
    /// Creates a new builder-style object to manufacture [`InspectorScoreDetails`](crate::types::InspectorScoreDetails).
    pub fn builder() -> crate::types::builders::InspectorScoreDetailsBuilder {
        crate::types::builders::InspectorScoreDetailsBuilder::default()
    }
}

/// A builder for [`InspectorScoreDetails`](crate::types::InspectorScoreDetails).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct InspectorScoreDetailsBuilder {
    pub(crate) adjusted_cvss: ::std::option::Option<crate::types::CvssScoreDetails>,
}
impl InspectorScoreDetailsBuilder {
    /// <p>An object that contains details about the CVSS score given to a finding.</p>
    pub fn adjusted_cvss(mut self, input: crate::types::CvssScoreDetails) -> Self {
        self.adjusted_cvss = ::std::option::Option::Some(input);
        self
    }
    /// <p>An object that contains details about the CVSS score given to a finding.</p>
    pub fn set_adjusted_cvss(mut self, input: ::std::option::Option<crate::types::CvssScoreDetails>) -> Self {
        self.adjusted_cvss = input;
        self
    }
    /// <p>An object that contains details about the CVSS score given to a finding.</p>
    pub fn get_adjusted_cvss(&self) -> &::std::option::Option<crate::types::CvssScoreDetails> {
        &self.adjusted_cvss
    }
    /// Consumes the builder and constructs a [`InspectorScoreDetails`](crate::types::InspectorScoreDetails).
    pub fn build(self) -> crate::types::InspectorScoreDetails {
        crate::types::InspectorScoreDetails {
            adjusted_cvss: self.adjusted_cvss,
        }
    }
}
