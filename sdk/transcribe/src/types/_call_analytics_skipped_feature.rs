// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Represents a skipped analytics feature during the analysis of a call analytics job.</p>
/// <p>The <code>Feature</code> field indicates the type of analytics feature that was skipped.</p>
/// <p>The <code>Message</code> field contains additional information or a message explaining why the analytics feature was skipped.</p>
/// <p>The <code>ReasonCode</code> field provides a code indicating the reason why the analytics feature was skipped.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CallAnalyticsSkippedFeature {
    /// <p>Indicates the type of analytics feature that was skipped during the analysis of a call analytics job.</p>
    pub feature: ::std::option::Option<crate::types::CallAnalyticsFeature>,
    /// <p>Provides a code indicating the reason why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub reason_code: ::std::option::Option<crate::types::CallAnalyticsSkippedReasonCode>,
    /// <p>Contains additional information or a message explaining why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub message: ::std::option::Option<::std::string::String>,
}
impl CallAnalyticsSkippedFeature {
    /// <p>Indicates the type of analytics feature that was skipped during the analysis of a call analytics job.</p>
    pub fn feature(&self) -> ::std::option::Option<&crate::types::CallAnalyticsFeature> {
        self.feature.as_ref()
    }
    /// <p>Provides a code indicating the reason why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn reason_code(&self) -> ::std::option::Option<&crate::types::CallAnalyticsSkippedReasonCode> {
        self.reason_code.as_ref()
    }
    /// <p>Contains additional information or a message explaining why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn message(&self) -> ::std::option::Option<&str> {
        self.message.as_deref()
    }
}
impl CallAnalyticsSkippedFeature {
    /// Creates a new builder-style object to manufacture [`CallAnalyticsSkippedFeature`](crate::types::CallAnalyticsSkippedFeature).
    pub fn builder() -> crate::types::builders::CallAnalyticsSkippedFeatureBuilder {
        crate::types::builders::CallAnalyticsSkippedFeatureBuilder::default()
    }
}

/// A builder for [`CallAnalyticsSkippedFeature`](crate::types::CallAnalyticsSkippedFeature).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CallAnalyticsSkippedFeatureBuilder {
    pub(crate) feature: ::std::option::Option<crate::types::CallAnalyticsFeature>,
    pub(crate) reason_code: ::std::option::Option<crate::types::CallAnalyticsSkippedReasonCode>,
    pub(crate) message: ::std::option::Option<::std::string::String>,
}
impl CallAnalyticsSkippedFeatureBuilder {
    /// <p>Indicates the type of analytics feature that was skipped during the analysis of a call analytics job.</p>
    pub fn feature(mut self, input: crate::types::CallAnalyticsFeature) -> Self {
        self.feature = ::std::option::Option::Some(input);
        self
    }
    /// <p>Indicates the type of analytics feature that was skipped during the analysis of a call analytics job.</p>
    pub fn set_feature(mut self, input: ::std::option::Option<crate::types::CallAnalyticsFeature>) -> Self {
        self.feature = input;
        self
    }
    /// <p>Indicates the type of analytics feature that was skipped during the analysis of a call analytics job.</p>
    pub fn get_feature(&self) -> &::std::option::Option<crate::types::CallAnalyticsFeature> {
        &self.feature
    }
    /// <p>Provides a code indicating the reason why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn reason_code(mut self, input: crate::types::CallAnalyticsSkippedReasonCode) -> Self {
        self.reason_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>Provides a code indicating the reason why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn set_reason_code(mut self, input: ::std::option::Option<crate::types::CallAnalyticsSkippedReasonCode>) -> Self {
        self.reason_code = input;
        self
    }
    /// <p>Provides a code indicating the reason why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn get_reason_code(&self) -> &::std::option::Option<crate::types::CallAnalyticsSkippedReasonCode> {
        &self.reason_code
    }
    /// <p>Contains additional information or a message explaining why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn message(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.message = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>Contains additional information or a message explaining why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn set_message(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.message = input;
        self
    }
    /// <p>Contains additional information or a message explaining why a specific analytics feature was skipped during the analysis of a call analytics job.</p>
    pub fn get_message(&self) -> &::std::option::Option<::std::string::String> {
        &self.message
    }
    /// Consumes the builder and constructs a [`CallAnalyticsSkippedFeature`](crate::types::CallAnalyticsSkippedFeature).
    pub fn build(self) -> crate::types::CallAnalyticsSkippedFeature {
        crate::types::CallAnalyticsSkippedFeature {
            feature: self.feature,
            reason_code: self.reason_code,
            message: self.message,
        }
    }
}
