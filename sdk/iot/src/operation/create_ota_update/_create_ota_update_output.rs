// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateOtaUpdateOutput {
    /// <p>The OTA update ID.</p>
    pub ota_update_id: ::std::option::Option<::std::string::String>,
    /// <p>The IoT job ID associated with the OTA update.</p>
    pub aws_iot_job_id: ::std::option::Option<::std::string::String>,
    /// <p>The OTA update ARN.</p>
    pub ota_update_arn: ::std::option::Option<::std::string::String>,
    /// <p>The IoT job ARN associated with the OTA update.</p>
    pub aws_iot_job_arn: ::std::option::Option<::std::string::String>,
    /// <p>The OTA update status.</p>
    pub ota_update_status: ::std::option::Option<crate::types::OtaUpdateStatus>,
    _request_id: Option<String>,
}
impl CreateOtaUpdateOutput {
    /// <p>The OTA update ID.</p>
    pub fn ota_update_id(&self) -> ::std::option::Option<&str> {
        self.ota_update_id.as_deref()
    }
    /// <p>The IoT job ID associated with the OTA update.</p>
    pub fn aws_iot_job_id(&self) -> ::std::option::Option<&str> {
        self.aws_iot_job_id.as_deref()
    }
    /// <p>The OTA update ARN.</p>
    pub fn ota_update_arn(&self) -> ::std::option::Option<&str> {
        self.ota_update_arn.as_deref()
    }
    /// <p>The IoT job ARN associated with the OTA update.</p>
    pub fn aws_iot_job_arn(&self) -> ::std::option::Option<&str> {
        self.aws_iot_job_arn.as_deref()
    }
    /// <p>The OTA update status.</p>
    pub fn ota_update_status(&self) -> ::std::option::Option<&crate::types::OtaUpdateStatus> {
        self.ota_update_status.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for CreateOtaUpdateOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateOtaUpdateOutput {
    /// Creates a new builder-style object to manufacture [`CreateOtaUpdateOutput`](crate::operation::create_ota_update::CreateOtaUpdateOutput).
    pub fn builder() -> crate::operation::create_ota_update::builders::CreateOtaUpdateOutputBuilder {
        crate::operation::create_ota_update::builders::CreateOtaUpdateOutputBuilder::default()
    }
}

/// A builder for [`CreateOtaUpdateOutput`](crate::operation::create_ota_update::CreateOtaUpdateOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateOtaUpdateOutputBuilder {
    pub(crate) ota_update_id: ::std::option::Option<::std::string::String>,
    pub(crate) aws_iot_job_id: ::std::option::Option<::std::string::String>,
    pub(crate) ota_update_arn: ::std::option::Option<::std::string::String>,
    pub(crate) aws_iot_job_arn: ::std::option::Option<::std::string::String>,
    pub(crate) ota_update_status: ::std::option::Option<crate::types::OtaUpdateStatus>,
    _request_id: Option<String>,
}
impl CreateOtaUpdateOutputBuilder {
    /// <p>The OTA update ID.</p>
    pub fn ota_update_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ota_update_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OTA update ID.</p>
    pub fn set_ota_update_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ota_update_id = input;
        self
    }
    /// <p>The OTA update ID.</p>
    pub fn get_ota_update_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ota_update_id
    }
    /// <p>The IoT job ID associated with the OTA update.</p>
    pub fn aws_iot_job_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_iot_job_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IoT job ID associated with the OTA update.</p>
    pub fn set_aws_iot_job_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_iot_job_id = input;
        self
    }
    /// <p>The IoT job ID associated with the OTA update.</p>
    pub fn get_aws_iot_job_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_iot_job_id
    }
    /// <p>The OTA update ARN.</p>
    pub fn ota_update_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ota_update_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The OTA update ARN.</p>
    pub fn set_ota_update_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ota_update_arn = input;
        self
    }
    /// <p>The OTA update ARN.</p>
    pub fn get_ota_update_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.ota_update_arn
    }
    /// <p>The IoT job ARN associated with the OTA update.</p>
    pub fn aws_iot_job_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.aws_iot_job_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The IoT job ARN associated with the OTA update.</p>
    pub fn set_aws_iot_job_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.aws_iot_job_arn = input;
        self
    }
    /// <p>The IoT job ARN associated with the OTA update.</p>
    pub fn get_aws_iot_job_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.aws_iot_job_arn
    }
    /// <p>The OTA update status.</p>
    pub fn ota_update_status(mut self, input: crate::types::OtaUpdateStatus) -> Self {
        self.ota_update_status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The OTA update status.</p>
    pub fn set_ota_update_status(mut self, input: ::std::option::Option<crate::types::OtaUpdateStatus>) -> Self {
        self.ota_update_status = input;
        self
    }
    /// <p>The OTA update status.</p>
    pub fn get_ota_update_status(&self) -> &::std::option::Option<crate::types::OtaUpdateStatus> {
        &self.ota_update_status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateOtaUpdateOutput`](crate::operation::create_ota_update::CreateOtaUpdateOutput).
    pub fn build(self) -> crate::operation::create_ota_update::CreateOtaUpdateOutput {
        crate::operation::create_ota_update::CreateOtaUpdateOutput {
            ota_update_id: self.ota_update_id,
            aws_iot_job_id: self.aws_iot_job_id,
            ota_update_arn: self.ota_update_arn,
            aws_iot_job_arn: self.aws_iot_job_arn,
            ota_update_status: self.ota_update_status,
            _request_id: self._request_id,
        }
    }
}
