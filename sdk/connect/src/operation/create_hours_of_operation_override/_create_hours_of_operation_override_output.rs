// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateHoursOfOperationOverrideOutput {
    /// <p>The identifier for the hours of operation override.</p>
    pub hours_of_operation_override_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateHoursOfOperationOverrideOutput {
    /// <p>The identifier for the hours of operation override.</p>
    pub fn hours_of_operation_override_id(&self) -> ::std::option::Option<&str> {
        self.hours_of_operation_override_id.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateHoursOfOperationOverrideOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateHoursOfOperationOverrideOutput {
    /// Creates a new builder-style object to manufacture [`CreateHoursOfOperationOverrideOutput`](crate::operation::create_hours_of_operation_override::CreateHoursOfOperationOverrideOutput).
    pub fn builder() -> crate::operation::create_hours_of_operation_override::builders::CreateHoursOfOperationOverrideOutputBuilder {
        crate::operation::create_hours_of_operation_override::builders::CreateHoursOfOperationOverrideOutputBuilder::default()
    }
}

/// A builder for [`CreateHoursOfOperationOverrideOutput`](crate::operation::create_hours_of_operation_override::CreateHoursOfOperationOverrideOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateHoursOfOperationOverrideOutputBuilder {
    pub(crate) hours_of_operation_override_id: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateHoursOfOperationOverrideOutputBuilder {
    /// <p>The identifier for the hours of operation override.</p>
    pub fn hours_of_operation_override_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hours_of_operation_override_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the hours of operation override.</p>
    pub fn set_hours_of_operation_override_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hours_of_operation_override_id = input;
        self
    }
    /// <p>The identifier for the hours of operation override.</p>
    pub fn get_hours_of_operation_override_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hours_of_operation_override_id
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateHoursOfOperationOverrideOutput`](crate::operation::create_hours_of_operation_override::CreateHoursOfOperationOverrideOutput).
    pub fn build(self) -> crate::operation::create_hours_of_operation_override::CreateHoursOfOperationOverrideOutput {
        crate::operation::create_hours_of_operation_override::CreateHoursOfOperationOverrideOutput {
            hours_of_operation_override_id: self.hours_of_operation_override_id,
            _request_id: self._request_id,
        }
    }
}
