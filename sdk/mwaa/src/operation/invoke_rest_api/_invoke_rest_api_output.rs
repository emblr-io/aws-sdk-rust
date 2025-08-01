// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq)]
pub struct InvokeRestApiOutput {
    /// <p>The HTTP status code returned by the Apache Airflow REST API call.</p>
    pub rest_api_status_code: ::std::option::Option<i32>,
    /// <p>The response data from the Apache Airflow REST API call, provided as a JSON object.</p>
    pub rest_api_response: ::std::option::Option<::aws_smithy_types::Document>,
    _request_id: Option<String>,
}
impl InvokeRestApiOutput {
    /// <p>The HTTP status code returned by the Apache Airflow REST API call.</p>
    pub fn rest_api_status_code(&self) -> ::std::option::Option<i32> {
        self.rest_api_status_code
    }
    /// <p>The response data from the Apache Airflow REST API call, provided as a JSON object.</p>
    pub fn rest_api_response(&self) -> ::std::option::Option<&::aws_smithy_types::Document> {
        self.rest_api_response.as_ref()
    }
}
impl ::std::fmt::Debug for InvokeRestApiOutput {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeRestApiOutput");
        formatter.field("rest_api_status_code", &self.rest_api_status_code);
        formatter.field("rest_api_response", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
impl ::aws_types::request_id::RequestId for InvokeRestApiOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl InvokeRestApiOutput {
    /// Creates a new builder-style object to manufacture [`InvokeRestApiOutput`](crate::operation::invoke_rest_api::InvokeRestApiOutput).
    pub fn builder() -> crate::operation::invoke_rest_api::builders::InvokeRestApiOutputBuilder {
        crate::operation::invoke_rest_api::builders::InvokeRestApiOutputBuilder::default()
    }
}

/// A builder for [`InvokeRestApiOutput`](crate::operation::invoke_rest_api::InvokeRestApiOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default)]
#[non_exhaustive]
pub struct InvokeRestApiOutputBuilder {
    pub(crate) rest_api_status_code: ::std::option::Option<i32>,
    pub(crate) rest_api_response: ::std::option::Option<::aws_smithy_types::Document>,
    _request_id: Option<String>,
}
impl InvokeRestApiOutputBuilder {
    /// <p>The HTTP status code returned by the Apache Airflow REST API call.</p>
    pub fn rest_api_status_code(mut self, input: i32) -> Self {
        self.rest_api_status_code = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status code returned by the Apache Airflow REST API call.</p>
    pub fn set_rest_api_status_code(mut self, input: ::std::option::Option<i32>) -> Self {
        self.rest_api_status_code = input;
        self
    }
    /// <p>The HTTP status code returned by the Apache Airflow REST API call.</p>
    pub fn get_rest_api_status_code(&self) -> &::std::option::Option<i32> {
        &self.rest_api_status_code
    }
    /// <p>The response data from the Apache Airflow REST API call, provided as a JSON object.</p>
    pub fn rest_api_response(mut self, input: ::aws_smithy_types::Document) -> Self {
        self.rest_api_response = ::std::option::Option::Some(input);
        self
    }
    /// <p>The response data from the Apache Airflow REST API call, provided as a JSON object.</p>
    pub fn set_rest_api_response(mut self, input: ::std::option::Option<::aws_smithy_types::Document>) -> Self {
        self.rest_api_response = input;
        self
    }
    /// <p>The response data from the Apache Airflow REST API call, provided as a JSON object.</p>
    pub fn get_rest_api_response(&self) -> &::std::option::Option<::aws_smithy_types::Document> {
        &self.rest_api_response
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`InvokeRestApiOutput`](crate::operation::invoke_rest_api::InvokeRestApiOutput).
    pub fn build(self) -> crate::operation::invoke_rest_api::InvokeRestApiOutput {
        crate::operation::invoke_rest_api::InvokeRestApiOutput {
            rest_api_status_code: self.rest_api_status_code,
            rest_api_response: self.rest_api_response,
            _request_id: self._request_id,
        }
    }
}
impl ::std::fmt::Debug for InvokeRestApiOutputBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        let mut formatter = f.debug_struct("InvokeRestApiOutputBuilder");
        formatter.field("rest_api_status_code", &self.rest_api_status_code);
        formatter.field("rest_api_response", &"*** Sensitive Data Redacted ***");
        formatter.field("_request_id", &self._request_id);
        formatter.finish()
    }
}
