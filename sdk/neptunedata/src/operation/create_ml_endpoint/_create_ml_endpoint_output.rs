// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateMlEndpointOutput {
    /// <p>The unique ID of the new inference endpoint.</p>
    pub id: ::std::option::Option<::std::string::String>,
    /// <p>The ARN for the new inference endpoint.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>The endpoint creation time, in milliseconds.</p>
    pub creation_time_in_millis: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl CreateMlEndpointOutput {
    /// <p>The unique ID of the new inference endpoint.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
    /// <p>The ARN for the new inference endpoint.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>The endpoint creation time, in milliseconds.</p>
    pub fn creation_time_in_millis(&self) -> ::std::option::Option<i64> {
        self.creation_time_in_millis
    }
}
impl ::aws_types::request_id::RequestId for CreateMlEndpointOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateMlEndpointOutput {
    /// Creates a new builder-style object to manufacture [`CreateMlEndpointOutput`](crate::operation::create_ml_endpoint::CreateMlEndpointOutput).
    pub fn builder() -> crate::operation::create_ml_endpoint::builders::CreateMlEndpointOutputBuilder {
        crate::operation::create_ml_endpoint::builders::CreateMlEndpointOutputBuilder::default()
    }
}

/// A builder for [`CreateMlEndpointOutput`](crate::operation::create_ml_endpoint::CreateMlEndpointOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateMlEndpointOutputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) creation_time_in_millis: ::std::option::Option<i64>,
    _request_id: Option<String>,
}
impl CreateMlEndpointOutputBuilder {
    /// <p>The unique ID of the new inference endpoint.</p>
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique ID of the new inference endpoint.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The unique ID of the new inference endpoint.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// <p>The ARN for the new inference endpoint.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN for the new inference endpoint.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The ARN for the new inference endpoint.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>The endpoint creation time, in milliseconds.</p>
    pub fn creation_time_in_millis(mut self, input: i64) -> Self {
        self.creation_time_in_millis = ::std::option::Option::Some(input);
        self
    }
    /// <p>The endpoint creation time, in milliseconds.</p>
    pub fn set_creation_time_in_millis(mut self, input: ::std::option::Option<i64>) -> Self {
        self.creation_time_in_millis = input;
        self
    }
    /// <p>The endpoint creation time, in milliseconds.</p>
    pub fn get_creation_time_in_millis(&self) -> &::std::option::Option<i64> {
        &self.creation_time_in_millis
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateMlEndpointOutput`](crate::operation::create_ml_endpoint::CreateMlEndpointOutput).
    pub fn build(self) -> crate::operation::create_ml_endpoint::CreateMlEndpointOutput {
        crate::operation::create_ml_endpoint::CreateMlEndpointOutput {
            id: self.id,
            arn: self.arn,
            creation_time_in_millis: self.creation_time_in_millis,
            _request_id: self._request_id,
        }
    }
}
