// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetInsightOutput {
    /// <p>The summary information of an insight.</p>
    pub insight: ::std::option::Option<crate::types::Insight>,
    _request_id: Option<String>,
}
impl GetInsightOutput {
    /// <p>The summary information of an insight.</p>
    pub fn insight(&self) -> ::std::option::Option<&crate::types::Insight> {
        self.insight.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetInsightOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetInsightOutput {
    /// Creates a new builder-style object to manufacture [`GetInsightOutput`](crate::operation::get_insight::GetInsightOutput).
    pub fn builder() -> crate::operation::get_insight::builders::GetInsightOutputBuilder {
        crate::operation::get_insight::builders::GetInsightOutputBuilder::default()
    }
}

/// A builder for [`GetInsightOutput`](crate::operation::get_insight::GetInsightOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetInsightOutputBuilder {
    pub(crate) insight: ::std::option::Option<crate::types::Insight>,
    _request_id: Option<String>,
}
impl GetInsightOutputBuilder {
    /// <p>The summary information of an insight.</p>
    pub fn insight(mut self, input: crate::types::Insight) -> Self {
        self.insight = ::std::option::Option::Some(input);
        self
    }
    /// <p>The summary information of an insight.</p>
    pub fn set_insight(mut self, input: ::std::option::Option<crate::types::Insight>) -> Self {
        self.insight = input;
        self
    }
    /// <p>The summary information of an insight.</p>
    pub fn get_insight(&self) -> &::std::option::Option<crate::types::Insight> {
        &self.insight
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetInsightOutput`](crate::operation::get_insight::GetInsightOutput).
    pub fn build(self) -> crate::operation::get_insight::GetInsightOutput {
        crate::operation::get_insight::GetInsightOutput {
            insight: self.insight,
            _request_id: self._request_id,
        }
    }
}
