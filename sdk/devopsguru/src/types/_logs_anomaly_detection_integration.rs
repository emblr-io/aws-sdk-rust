// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about the integration of DevOps Guru with CloudWatch log groups for log anomaly detection.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct LogsAnomalyDetectionIntegration {
    /// <p>Specifies if DevOps Guru is configured to perform log anomaly detection on CloudWatch log groups.</p>
    pub opt_in_status: ::std::option::Option<crate::types::OptInStatus>,
}
impl LogsAnomalyDetectionIntegration {
    /// <p>Specifies if DevOps Guru is configured to perform log anomaly detection on CloudWatch log groups.</p>
    pub fn opt_in_status(&self) -> ::std::option::Option<&crate::types::OptInStatus> {
        self.opt_in_status.as_ref()
    }
}
impl LogsAnomalyDetectionIntegration {
    /// Creates a new builder-style object to manufacture [`LogsAnomalyDetectionIntegration`](crate::types::LogsAnomalyDetectionIntegration).
    pub fn builder() -> crate::types::builders::LogsAnomalyDetectionIntegrationBuilder {
        crate::types::builders::LogsAnomalyDetectionIntegrationBuilder::default()
    }
}

/// A builder for [`LogsAnomalyDetectionIntegration`](crate::types::LogsAnomalyDetectionIntegration).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct LogsAnomalyDetectionIntegrationBuilder {
    pub(crate) opt_in_status: ::std::option::Option<crate::types::OptInStatus>,
}
impl LogsAnomalyDetectionIntegrationBuilder {
    /// <p>Specifies if DevOps Guru is configured to perform log anomaly detection on CloudWatch log groups.</p>
    pub fn opt_in_status(mut self, input: crate::types::OptInStatus) -> Self {
        self.opt_in_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>Specifies if DevOps Guru is configured to perform log anomaly detection on CloudWatch log groups.</p>
    pub fn set_opt_in_status(mut self, input: ::std::option::Option<crate::types::OptInStatus>) -> Self {
        self.opt_in_status = input;
        self
    }
    /// <p>Specifies if DevOps Guru is configured to perform log anomaly detection on CloudWatch log groups.</p>
    pub fn get_opt_in_status(&self) -> &::std::option::Option<crate::types::OptInStatus> {
        &self.opt_in_status
    }
    /// Consumes the builder and constructs a [`LogsAnomalyDetectionIntegration`](crate::types::LogsAnomalyDetectionIntegration).
    pub fn build(self) -> crate::types::LogsAnomalyDetectionIntegration {
        crate::types::LogsAnomalyDetectionIntegration {
            opt_in_status: self.opt_in_status,
        }
    }
}
