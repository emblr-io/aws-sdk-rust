// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns a summary of information about an enabled control.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct EnabledControlSummary {
    /// <p>The <code>controlIdentifier</code> of the enabled control.</p>
    pub control_identifier: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the enabled control.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The ARN of the organizational unit.</p>
    pub target_identifier: ::std::option::Option<::std::string::String>,
    /// <p>A short description of the status of the enabled control.</p>
    pub status_summary: ::std::option::Option<crate::types::EnablementStatusSummary>,
    /// <p>The drift status of the enabled control.</p>
    pub drift_status_summary: ::std::option::Option<crate::types::DriftStatusSummary>,
}
impl EnabledControlSummary {
    /// <p>The <code>controlIdentifier</code> of the enabled control.</p>
    pub fn control_identifier(&self) -> ::std::option::Option<&str> {
        self.control_identifier.as_deref()
    }
    /// <p>The ARN of the enabled control.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The ARN of the organizational unit.</p>
    pub fn target_identifier(&self) -> ::std::option::Option<&str> {
        self.target_identifier.as_deref()
    }
    /// <p>A short description of the status of the enabled control.</p>
    pub fn status_summary(&self) -> ::std::option::Option<&crate::types::EnablementStatusSummary> {
        self.status_summary.as_ref()
    }
    /// <p>The drift status of the enabled control.</p>
    pub fn drift_status_summary(&self) -> ::std::option::Option<&crate::types::DriftStatusSummary> {
        self.drift_status_summary.as_ref()
    }
}
impl EnabledControlSummary {
    /// Creates a new builder-style object to manufacture [`EnabledControlSummary`](crate::types::EnabledControlSummary).
    pub fn builder() -> crate::types::builders::EnabledControlSummaryBuilder {
        crate::types::builders::EnabledControlSummaryBuilder::default()
    }
}

/// A builder for [`EnabledControlSummary`](crate::types::EnabledControlSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct EnabledControlSummaryBuilder {
    pub(crate) control_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) target_identifier: ::std::option::Option<::std::string::String>,
    pub(crate) status_summary: ::std::option::Option<crate::types::EnablementStatusSummary>,
    pub(crate) drift_status_summary: ::std::option::Option<crate::types::DriftStatusSummary>,
}
impl EnabledControlSummaryBuilder {
    /// <p>The <code>controlIdentifier</code> of the enabled control.</p>
    pub fn control_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.control_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>controlIdentifier</code> of the enabled control.</p>
    pub fn set_control_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.control_identifier = input;
        self
    }
    /// <p>The <code>controlIdentifier</code> of the enabled control.</p>
    pub fn get_control_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.control_identifier
    }
    /// <p>The ARN of the enabled control.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the enabled control.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN of the enabled control.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The ARN of the organizational unit.</p>
    pub fn target_identifier(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.target_identifier = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the organizational unit.</p>
    pub fn set_target_identifier(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.target_identifier = input;
        self
    }
    /// <p>The ARN of the organizational unit.</p>
    pub fn get_target_identifier(&self) -> &::std::option::Option<::std::string::String> {
        &self.target_identifier
    }
    /// <p>A short description of the status of the enabled control.</p>
    pub fn status_summary(mut self, input: crate::types::EnablementStatusSummary) -> Self {
        self.status_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>A short description of the status of the enabled control.</p>
    pub fn set_status_summary(mut self, input: ::std::option::Option<crate::types::EnablementStatusSummary>) -> Self {
        self.status_summary = input;
        self
    }
    /// <p>A short description of the status of the enabled control.</p>
    pub fn get_status_summary(&self) -> &::std::option::Option<crate::types::EnablementStatusSummary> {
        &self.status_summary
    }
    /// <p>The drift status of the enabled control.</p>
    pub fn drift_status_summary(mut self, input: crate::types::DriftStatusSummary) -> Self {
        self.drift_status_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>The drift status of the enabled control.</p>
    pub fn set_drift_status_summary(mut self, input: ::std::option::Option<crate::types::DriftStatusSummary>) -> Self {
        self.drift_status_summary = input;
        self
    }
    /// <p>The drift status of the enabled control.</p>
    pub fn get_drift_status_summary(&self) -> &::std::option::Option<crate::types::DriftStatusSummary> {
        &self.drift_status_summary
    }
    /// Consumes the builder and constructs a [`EnabledControlSummary`](crate::types::EnabledControlSummary).
    pub fn build(self) -> crate::types::EnabledControlSummary {
        crate::types::EnabledControlSummary {
            control_identifier: self.control_identifier,
            arn: self.arn,
            target_identifier: self.target_identifier,
            status_summary: self.status_summary,
            drift_status_summary: self.drift_status_summary,
        }
    }
}
