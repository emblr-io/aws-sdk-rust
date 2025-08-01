// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteThreatIntelSetInput {
    /// <p>The unique ID of the detector that is associated with the threatIntelSet.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub detector_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique ID of the threatIntelSet that you want to delete.</p>
    pub threat_intel_set_id: ::std::option::Option<::std::string::String>,
}
impl DeleteThreatIntelSetInput {
    /// <p>The unique ID of the detector that is associated with the threatIntelSet.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn detector_id(&self) -> ::std::option::Option<&str> {
        self.detector_id.as_deref()
    }
    /// <p>The unique ID of the threatIntelSet that you want to delete.</p>
    pub fn threat_intel_set_id(&self) -> ::std::option::Option<&str> {
        self.threat_intel_set_id.as_deref()
    }
}
impl DeleteThreatIntelSetInput {
    /// Creates a new builder-style object to manufacture [`DeleteThreatIntelSetInput`](crate::operation::delete_threat_intel_set::DeleteThreatIntelSetInput).
    pub fn builder() -> crate::operation::delete_threat_intel_set::builders::DeleteThreatIntelSetInputBuilder {
        crate::operation::delete_threat_intel_set::builders::DeleteThreatIntelSetInputBuilder::default()
    }
}

/// A builder for [`DeleteThreatIntelSetInput`](crate::operation::delete_threat_intel_set::DeleteThreatIntelSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteThreatIntelSetInputBuilder {
    pub(crate) detector_id: ::std::option::Option<::std::string::String>,
    pub(crate) threat_intel_set_id: ::std::option::Option<::std::string::String>,
}
impl DeleteThreatIntelSetInputBuilder {
    /// <p>The unique ID of the detector that is associated with the threatIntelSet.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    /// This field is required.
    pub fn detector_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.detector_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the detector that is associated with the threatIntelSet.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn set_detector_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.detector_id = input;
        self
    }
    /// <p>The unique ID of the detector that is associated with the threatIntelSet.</p>
    /// <p>To find the <code>detectorId</code> in the current Region, see the Settings page in the GuardDuty console, or run the <a href="https://docs.aws.amazon.com/guardduty/latest/APIReference/API_ListDetectors.html">ListDetectors</a> API.</p>
    pub fn get_detector_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.detector_id
    }
    /// <p>The unique ID of the threatIntelSet that you want to delete.</p>
    /// This field is required.
    pub fn threat_intel_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.threat_intel_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the threatIntelSet that you want to delete.</p>
    pub fn set_threat_intel_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.threat_intel_set_id = input;
        self
    }
    /// <p>The unique ID of the threatIntelSet that you want to delete.</p>
    pub fn get_threat_intel_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.threat_intel_set_id
    }
    /// Consumes the builder and constructs a [`DeleteThreatIntelSetInput`](crate::operation::delete_threat_intel_set::DeleteThreatIntelSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_threat_intel_set::DeleteThreatIntelSetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_threat_intel_set::DeleteThreatIntelSetInput {
            detector_id: self.detector_id,
            threat_intel_set_id: self.threat_intel_set_id,
        })
    }
}
