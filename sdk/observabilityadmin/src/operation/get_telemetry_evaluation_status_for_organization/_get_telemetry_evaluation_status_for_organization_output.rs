// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetTelemetryEvaluationStatusForOrganizationOutput {
    /// <p>The onboarding status of the telemetry config feature for the organization.</p>
    pub status: ::std::option::Option<crate::types::Status>,
    /// <p>This field describes the reason for the failure status. The field will only be populated if <code>Status</code> is <code>FAILED_START</code> or <code>FAILED_STOP</code>.</p>
    pub failure_reason: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetTelemetryEvaluationStatusForOrganizationOutput {
    /// <p>The onboarding status of the telemetry config feature for the organization.</p>
    pub fn status(&self) -> ::std::option::Option<&crate::types::Status> {
        self.status.as_ref()
    }
    /// <p>This field describes the reason for the failure status. The field will only be populated if <code>Status</code> is <code>FAILED_START</code> or <code>FAILED_STOP</code>.</p>
    pub fn failure_reason(&self) -> ::std::option::Option<&str> {
        self.failure_reason.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for GetTelemetryEvaluationStatusForOrganizationOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetTelemetryEvaluationStatusForOrganizationOutput {
    /// Creates a new builder-style object to manufacture [`GetTelemetryEvaluationStatusForOrganizationOutput`](crate::operation::get_telemetry_evaluation_status_for_organization::GetTelemetryEvaluationStatusForOrganizationOutput).
    pub fn builder(
    ) -> crate::operation::get_telemetry_evaluation_status_for_organization::builders::GetTelemetryEvaluationStatusForOrganizationOutputBuilder {
        crate::operation::get_telemetry_evaluation_status_for_organization::builders::GetTelemetryEvaluationStatusForOrganizationOutputBuilder::default()
    }
}

/// A builder for [`GetTelemetryEvaluationStatusForOrganizationOutput`](crate::operation::get_telemetry_evaluation_status_for_organization::GetTelemetryEvaluationStatusForOrganizationOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetTelemetryEvaluationStatusForOrganizationOutputBuilder {
    pub(crate) status: ::std::option::Option<crate::types::Status>,
    pub(crate) failure_reason: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl GetTelemetryEvaluationStatusForOrganizationOutputBuilder {
    /// <p>The onboarding status of the telemetry config feature for the organization.</p>
    pub fn status(mut self, input: crate::types::Status) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The onboarding status of the telemetry config feature for the organization.</p>
    pub fn set_status(mut self, input: ::std::option::Option<crate::types::Status>) -> Self {
        self.status = input;
        self
    }
    /// <p>The onboarding status of the telemetry config feature for the organization.</p>
    pub fn get_status(&self) -> &::std::option::Option<crate::types::Status> {
        &self.status
    }
    /// <p>This field describes the reason for the failure status. The field will only be populated if <code>Status</code> is <code>FAILED_START</code> or <code>FAILED_STOP</code>.</p>
    pub fn failure_reason(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.failure_reason = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>This field describes the reason for the failure status. The field will only be populated if <code>Status</code> is <code>FAILED_START</code> or <code>FAILED_STOP</code>.</p>
    pub fn set_failure_reason(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.failure_reason = input;
        self
    }
    /// <p>This field describes the reason for the failure status. The field will only be populated if <code>Status</code> is <code>FAILED_START</code> or <code>FAILED_STOP</code>.</p>
    pub fn get_failure_reason(&self) -> &::std::option::Option<::std::string::String> {
        &self.failure_reason
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetTelemetryEvaluationStatusForOrganizationOutput`](crate::operation::get_telemetry_evaluation_status_for_organization::GetTelemetryEvaluationStatusForOrganizationOutput).
    pub fn build(self) -> crate::operation::get_telemetry_evaluation_status_for_organization::GetTelemetryEvaluationStatusForOrganizationOutput {
        crate::operation::get_telemetry_evaluation_status_for_organization::GetTelemetryEvaluationStatusForOrganizationOutput {
            status: self.status,
            failure_reason: self.failure_reason,
            _request_id: self._request_id,
        }
    }
}
