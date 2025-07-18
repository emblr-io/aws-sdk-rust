// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StartIncidentOutput {
    /// <p>The ARN of the newly created incident record.</p>
    pub incident_record_arn: ::std::string::String,
    _request_id: Option<String>,
}
impl StartIncidentOutput {
    /// <p>The ARN of the newly created incident record.</p>
    pub fn incident_record_arn(&self) -> &str {
        use std::ops::Deref;
        self.incident_record_arn.deref()
    }
}
impl ::aws_types::request_id::RequestId for StartIncidentOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StartIncidentOutput {
    /// Creates a new builder-style object to manufacture [`StartIncidentOutput`](crate::operation::start_incident::StartIncidentOutput).
    pub fn builder() -> crate::operation::start_incident::builders::StartIncidentOutputBuilder {
        crate::operation::start_incident::builders::StartIncidentOutputBuilder::default()
    }
}

/// A builder for [`StartIncidentOutput`](crate::operation::start_incident::StartIncidentOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StartIncidentOutputBuilder {
    pub(crate) incident_record_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl StartIncidentOutputBuilder {
    /// <p>The ARN of the newly created incident record.</p>
    /// This field is required.
    pub fn incident_record_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.incident_record_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the newly created incident record.</p>
    pub fn set_incident_record_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.incident_record_arn = input;
        self
    }
    /// <p>The ARN of the newly created incident record.</p>
    pub fn get_incident_record_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.incident_record_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StartIncidentOutput`](crate::operation::start_incident::StartIncidentOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`incident_record_arn`](crate::operation::start_incident::builders::StartIncidentOutputBuilder::incident_record_arn)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::start_incident::StartIncidentOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::start_incident::StartIncidentOutput {
            incident_record_arn: self.incident_record_arn.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "incident_record_arn",
                    "incident_record_arn was not specified but it is required when building StartIncidentOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
