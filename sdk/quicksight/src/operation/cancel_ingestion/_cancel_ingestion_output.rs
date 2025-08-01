// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CancelIngestionOutput {
    /// <p>The Amazon Resource Name (ARN) for the data ingestion.</p>
    pub arn: ::std::option::Option<::std::string::String>,
    /// <p>An ID for the ingestion.</p>
    pub ingestion_id: ::std::option::Option<::std::string::String>,
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub request_id: ::std::option::Option<::std::string::String>,
    /// <p>The HTTP status of the request.</p>
    pub status: i32,
    _request_id: Option<String>,
}
impl CancelIngestionOutput {
    /// <p>The Amazon Resource Name (ARN) for the data ingestion.</p>
    pub fn arn(&self) -> ::std::option::Option<&str> {
        self.arn.as_deref()
    }
    /// <p>An ID for the ingestion.</p>
    pub fn ingestion_id(&self) -> ::std::option::Option<&str> {
        self.ingestion_id.as_deref()
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(&self) -> ::std::option::Option<&str> {
        self.request_id.as_deref()
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(&self) -> i32 {
        self.status
    }
}
impl ::aws_types::request_id::RequestId for CancelIngestionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CancelIngestionOutput {
    /// Creates a new builder-style object to manufacture [`CancelIngestionOutput`](crate::operation::cancel_ingestion::CancelIngestionOutput).
    pub fn builder() -> crate::operation::cancel_ingestion::builders::CancelIngestionOutputBuilder {
        crate::operation::cancel_ingestion::builders::CancelIngestionOutputBuilder::default()
    }
}

/// A builder for [`CancelIngestionOutput`](crate::operation::cancel_ingestion::CancelIngestionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CancelIngestionOutputBuilder {
    pub(crate) arn: ::std::option::Option<::std::string::String>,
    pub(crate) ingestion_id: ::std::option::Option<::std::string::String>,
    pub(crate) request_id: ::std::option::Option<::std::string::String>,
    pub(crate) status: ::std::option::Option<i32>,
    _request_id: Option<String>,
}
impl CancelIngestionOutputBuilder {
    /// <p>The Amazon Resource Name (ARN) for the data ingestion.</p>
    pub fn arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the data ingestion.</p>
    pub fn set_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.arn = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) for the data ingestion.</p>
    pub fn get_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.arn
    }
    /// <p>An ID for the ingestion.</p>
    pub fn ingestion_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.ingestion_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>An ID for the ingestion.</p>
    pub fn set_ingestion_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.ingestion_id = input;
        self
    }
    /// <p>An ID for the ingestion.</p>
    pub fn get_ingestion_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.ingestion_id
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn request_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.request_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn set_request_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.request_id = input;
        self
    }
    /// <p>The Amazon Web Services request ID for this operation.</p>
    pub fn get_request_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.request_id
    }
    /// <p>The HTTP status of the request.</p>
    pub fn status(mut self, input: i32) -> Self {
        self.status = ::std::option::Option::Some(input);
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn set_status(mut self, input: ::std::option::Option<i32>) -> Self {
        self.status = input;
        self
    }
    /// <p>The HTTP status of the request.</p>
    pub fn get_status(&self) -> &::std::option::Option<i32> {
        &self.status
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CancelIngestionOutput`](crate::operation::cancel_ingestion::CancelIngestionOutput).
    pub fn build(self) -> crate::operation::cancel_ingestion::CancelIngestionOutput {
        crate::operation::cancel_ingestion::CancelIngestionOutput {
            arn: self.arn,
            ingestion_id: self.ingestion_id,
            request_id: self.request_id,
            status: self.status.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
