// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateFunctionOutput {
    /// <p>Contains configuration information and metadata about a CloudFront function.</p>
    pub function_summary: ::std::option::Option<crate::types::FunctionSummary>,
    /// <p>The URL of the CloudFront function. Use the URL to manage the function with the CloudFront API.</p>
    pub location: ::std::option::Option<::std::string::String>,
    /// <p>The version identifier for the current version of the CloudFront function.</p>
    pub e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateFunctionOutput {
    /// <p>Contains configuration information and metadata about a CloudFront function.</p>
    pub fn function_summary(&self) -> ::std::option::Option<&crate::types::FunctionSummary> {
        self.function_summary.as_ref()
    }
    /// <p>The URL of the CloudFront function. Use the URL to manage the function with the CloudFront API.</p>
    pub fn location(&self) -> ::std::option::Option<&str> {
        self.location.as_deref()
    }
    /// <p>The version identifier for the current version of the CloudFront function.</p>
    pub fn e_tag(&self) -> ::std::option::Option<&str> {
        self.e_tag.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateFunctionOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateFunctionOutput {
    /// Creates a new builder-style object to manufacture [`CreateFunctionOutput`](crate::operation::create_function::CreateFunctionOutput).
    pub fn builder() -> crate::operation::create_function::builders::CreateFunctionOutputBuilder {
        crate::operation::create_function::builders::CreateFunctionOutputBuilder::default()
    }
}

/// A builder for [`CreateFunctionOutput`](crate::operation::create_function::CreateFunctionOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateFunctionOutputBuilder {
    pub(crate) function_summary: ::std::option::Option<crate::types::FunctionSummary>,
    pub(crate) location: ::std::option::Option<::std::string::String>,
    pub(crate) e_tag: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateFunctionOutputBuilder {
    /// <p>Contains configuration information and metadata about a CloudFront function.</p>
    pub fn function_summary(mut self, input: crate::types::FunctionSummary) -> Self {
        self.function_summary = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains configuration information and metadata about a CloudFront function.</p>
    pub fn set_function_summary(mut self, input: ::std::option::Option<crate::types::FunctionSummary>) -> Self {
        self.function_summary = input;
        self
    }
    /// <p>Contains configuration information and metadata about a CloudFront function.</p>
    pub fn get_function_summary(&self) -> &::std::option::Option<crate::types::FunctionSummary> {
        &self.function_summary
    }
    /// <p>The URL of the CloudFront function. Use the URL to manage the function with the CloudFront API.</p>
    pub fn location(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.location = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The URL of the CloudFront function. Use the URL to manage the function with the CloudFront API.</p>
    pub fn set_location(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.location = input;
        self
    }
    /// <p>The URL of the CloudFront function. Use the URL to manage the function with the CloudFront API.</p>
    pub fn get_location(&self) -> &::std::option::Option<::std::string::String> {
        &self.location
    }
    /// <p>The version identifier for the current version of the CloudFront function.</p>
    pub fn e_tag(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.e_tag = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The version identifier for the current version of the CloudFront function.</p>
    pub fn set_e_tag(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.e_tag = input;
        self
    }
    /// <p>The version identifier for the current version of the CloudFront function.</p>
    pub fn get_e_tag(&self) -> &::std::option::Option<::std::string::String> {
        &self.e_tag
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateFunctionOutput`](crate::operation::create_function::CreateFunctionOutput).
    pub fn build(self) -> crate::operation::create_function::CreateFunctionOutput {
        crate::operation::create_function::CreateFunctionOutput {
            function_summary: self.function_summary,
            location: self.location,
            e_tag: self.e_tag,
            _request_id: self._request_id,
        }
    }
}
