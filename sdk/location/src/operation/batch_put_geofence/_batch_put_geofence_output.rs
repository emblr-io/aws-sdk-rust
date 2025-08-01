// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct BatchPutGeofenceOutput {
    /// <p>Contains each geofence that was successfully stored in a geofence collection.</p>
    pub successes: ::std::vec::Vec<crate::types::BatchPutGeofenceSuccess>,
    /// <p>Contains additional error details for each geofence that failed to be stored in a geofence collection.</p>
    pub errors: ::std::vec::Vec<crate::types::BatchPutGeofenceError>,
    _request_id: Option<String>,
}
impl BatchPutGeofenceOutput {
    /// <p>Contains each geofence that was successfully stored in a geofence collection.</p>
    pub fn successes(&self) -> &[crate::types::BatchPutGeofenceSuccess] {
        use std::ops::Deref;
        self.successes.deref()
    }
    /// <p>Contains additional error details for each geofence that failed to be stored in a geofence collection.</p>
    pub fn errors(&self) -> &[crate::types::BatchPutGeofenceError] {
        use std::ops::Deref;
        self.errors.deref()
    }
}
impl ::aws_types::request_id::RequestId for BatchPutGeofenceOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl BatchPutGeofenceOutput {
    /// Creates a new builder-style object to manufacture [`BatchPutGeofenceOutput`](crate::operation::batch_put_geofence::BatchPutGeofenceOutput).
    pub fn builder() -> crate::operation::batch_put_geofence::builders::BatchPutGeofenceOutputBuilder {
        crate::operation::batch_put_geofence::builders::BatchPutGeofenceOutputBuilder::default()
    }
}

/// A builder for [`BatchPutGeofenceOutput`](crate::operation::batch_put_geofence::BatchPutGeofenceOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct BatchPutGeofenceOutputBuilder {
    pub(crate) successes: ::std::option::Option<::std::vec::Vec<crate::types::BatchPutGeofenceSuccess>>,
    pub(crate) errors: ::std::option::Option<::std::vec::Vec<crate::types::BatchPutGeofenceError>>,
    _request_id: Option<String>,
}
impl BatchPutGeofenceOutputBuilder {
    /// Appends an item to `successes`.
    ///
    /// To override the contents of this collection use [`set_successes`](Self::set_successes).
    ///
    /// <p>Contains each geofence that was successfully stored in a geofence collection.</p>
    pub fn successes(mut self, input: crate::types::BatchPutGeofenceSuccess) -> Self {
        let mut v = self.successes.unwrap_or_default();
        v.push(input);
        self.successes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains each geofence that was successfully stored in a geofence collection.</p>
    pub fn set_successes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchPutGeofenceSuccess>>) -> Self {
        self.successes = input;
        self
    }
    /// <p>Contains each geofence that was successfully stored in a geofence collection.</p>
    pub fn get_successes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchPutGeofenceSuccess>> {
        &self.successes
    }
    /// Appends an item to `errors`.
    ///
    /// To override the contents of this collection use [`set_errors`](Self::set_errors).
    ///
    /// <p>Contains additional error details for each geofence that failed to be stored in a geofence collection.</p>
    pub fn errors(mut self, input: crate::types::BatchPutGeofenceError) -> Self {
        let mut v = self.errors.unwrap_or_default();
        v.push(input);
        self.errors = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains additional error details for each geofence that failed to be stored in a geofence collection.</p>
    pub fn set_errors(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::BatchPutGeofenceError>>) -> Self {
        self.errors = input;
        self
    }
    /// <p>Contains additional error details for each geofence that failed to be stored in a geofence collection.</p>
    pub fn get_errors(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::BatchPutGeofenceError>> {
        &self.errors
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`BatchPutGeofenceOutput`](crate::operation::batch_put_geofence::BatchPutGeofenceOutput).
    /// This method will fail if any of the following fields are not set:
    /// - [`successes`](crate::operation::batch_put_geofence::builders::BatchPutGeofenceOutputBuilder::successes)
    /// - [`errors`](crate::operation::batch_put_geofence::builders::BatchPutGeofenceOutputBuilder::errors)
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::batch_put_geofence::BatchPutGeofenceOutput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::batch_put_geofence::BatchPutGeofenceOutput {
            successes: self.successes.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "successes",
                    "successes was not specified but it is required when building BatchPutGeofenceOutput",
                )
            })?,
            errors: self.errors.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "errors",
                    "errors was not specified but it is required when building BatchPutGeofenceOutput",
                )
            })?,
            _request_id: self._request_id,
        })
    }
}
