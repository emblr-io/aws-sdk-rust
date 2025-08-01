// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Details on adjustments Amazon Inspector made to the CVSS score for a finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CvssScoreAdjustment {
    /// <p>The metric used to adjust the CVSS score.</p>
    pub metric: ::std::option::Option<::std::string::String>,
    /// <p>The reason the CVSS score has been adjustment.</p>
    pub reason: ::std::option::Option<::std::string::String>,
}
impl CvssScoreAdjustment {
    /// <p>The metric used to adjust the CVSS score.</p>
    pub fn metric(&self) -> ::std::option::Option<&str> {
        self.metric.as_deref()
    }
    /// <p>The reason the CVSS score has been adjustment.</p>
    pub fn reason(&self) -> ::std::option::Option<&str> {
        self.reason.as_deref()
    }
}
impl CvssScoreAdjustment {
    /// Creates a new builder-style object to manufacture [`CvssScoreAdjustment`](crate::types::CvssScoreAdjustment).
    pub fn builder() -> crate::types::builders::CvssScoreAdjustmentBuilder {
        crate::types::builders::CvssScoreAdjustmentBuilder::default()
    }
}

/// A builder for [`CvssScoreAdjustment`](crate::types::CvssScoreAdjustment).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CvssScoreAdjustmentBuilder {
    pub(crate) metric: ::std::option::Option<::std::string::String>,
    pub(crate) reason: ::std::option::Option<::std::string::String>,
}
impl CvssScoreAdjustmentBuilder {
    /// <p>The metric used to adjust the CVSS score.</p>
    pub fn metric(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.metric = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The metric used to adjust the CVSS score.</p>
    pub fn set_metric(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.metric = input;
        self
    }
    /// <p>The metric used to adjust the CVSS score.</p>
    pub fn get_metric(&self) -> &::std::option::Option<::std::string::String> {
        &self.metric
    }
    /// <p>The reason the CVSS score has been adjustment.</p>
    pub fn reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The reason the CVSS score has been adjustment.</p>
    pub fn set_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.reason = input;
        self
    }
    /// <p>The reason the CVSS score has been adjustment.</p>
    pub fn get_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.reason
    }
    /// Consumes the builder and constructs a [`CvssScoreAdjustment`](crate::types::CvssScoreAdjustment).
    pub fn build(self) -> crate::types::CvssScoreAdjustment {
        crate::types::CvssScoreAdjustment {
            metric: self.metric,
            reason: self.reason,
        }
    }
}
