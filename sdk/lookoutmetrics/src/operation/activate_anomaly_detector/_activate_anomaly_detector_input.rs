// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ActivateAnomalyDetectorInput {
    /// <p>The ARN of the anomaly detector.</p>
    pub anomaly_detector_arn: ::std::option::Option<::std::string::String>,
}
impl ActivateAnomalyDetectorInput {
    /// <p>The ARN of the anomaly detector.</p>
    pub fn anomaly_detector_arn(&self) -> ::std::option::Option<&str> {
        self.anomaly_detector_arn.as_deref()
    }
}
impl ActivateAnomalyDetectorInput {
    /// Creates a new builder-style object to manufacture [`ActivateAnomalyDetectorInput`](crate::operation::activate_anomaly_detector::ActivateAnomalyDetectorInput).
    pub fn builder() -> crate::operation::activate_anomaly_detector::builders::ActivateAnomalyDetectorInputBuilder {
        crate::operation::activate_anomaly_detector::builders::ActivateAnomalyDetectorInputBuilder::default()
    }
}

/// A builder for [`ActivateAnomalyDetectorInput`](crate::operation::activate_anomaly_detector::ActivateAnomalyDetectorInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ActivateAnomalyDetectorInputBuilder {
    pub(crate) anomaly_detector_arn: ::std::option::Option<::std::string::String>,
}
impl ActivateAnomalyDetectorInputBuilder {
    /// <p>The ARN of the anomaly detector.</p>
    /// This field is required.
    pub fn anomaly_detector_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.anomaly_detector_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the anomaly detector.</p>
    pub fn set_anomaly_detector_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.anomaly_detector_arn = input;
        self
    }
    /// <p>The ARN of the anomaly detector.</p>
    pub fn get_anomaly_detector_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.anomaly_detector_arn
    }
    /// Consumes the builder and constructs a [`ActivateAnomalyDetectorInput`](crate::operation::activate_anomaly_detector::ActivateAnomalyDetectorInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::activate_anomaly_detector::ActivateAnomalyDetectorInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::activate_anomaly_detector::ActivateAnomalyDetectorInput {
            anomaly_detector_arn: self.anomaly_detector_arn,
        })
    }
}
