// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CreateInsightOutput {
    /// <p>The ARN of the insight created.</p>
    pub insight_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateInsightOutput {
    /// <p>The ARN of the insight created.</p>
    pub fn insight_arn(&self) -> ::std::option::Option<&str> {
        self.insight_arn.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for CreateInsightOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl CreateInsightOutput {
    /// Creates a new builder-style object to manufacture [`CreateInsightOutput`](crate::operation::create_insight::CreateInsightOutput).
    pub fn builder() -> crate::operation::create_insight::builders::CreateInsightOutputBuilder {
        crate::operation::create_insight::builders::CreateInsightOutputBuilder::default()
    }
}

/// A builder for [`CreateInsightOutput`](crate::operation::create_insight::CreateInsightOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CreateInsightOutputBuilder {
    pub(crate) insight_arn: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl CreateInsightOutputBuilder {
    /// <p>The ARN of the insight created.</p>
    /// This field is required.
    pub fn insight_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.insight_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of the insight created.</p>
    pub fn set_insight_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.insight_arn = input;
        self
    }
    /// <p>The ARN of the insight created.</p>
    pub fn get_insight_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.insight_arn
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`CreateInsightOutput`](crate::operation::create_insight::CreateInsightOutput).
    pub fn build(self) -> crate::operation::create_insight::CreateInsightOutput {
        crate::operation::create_insight::CreateInsightOutput {
            insight_arn: self.insight_arn,
            _request_id: self._request_id,
        }
    }
}
