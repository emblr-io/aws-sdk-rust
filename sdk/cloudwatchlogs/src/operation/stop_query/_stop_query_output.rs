// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct StopQueryOutput {
    /// <p>This is true if the query was stopped by the <code>StopQuery</code> operation.</p>
    pub success: bool,
    _request_id: Option<String>,
}
impl StopQueryOutput {
    /// <p>This is true if the query was stopped by the <code>StopQuery</code> operation.</p>
    pub fn success(&self) -> bool {
        self.success
    }
}
impl ::aws_types::request_id::RequestId for StopQueryOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl StopQueryOutput {
    /// Creates a new builder-style object to manufacture [`StopQueryOutput`](crate::operation::stop_query::StopQueryOutput).
    pub fn builder() -> crate::operation::stop_query::builders::StopQueryOutputBuilder {
        crate::operation::stop_query::builders::StopQueryOutputBuilder::default()
    }
}

/// A builder for [`StopQueryOutput`](crate::operation::stop_query::StopQueryOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct StopQueryOutputBuilder {
    pub(crate) success: ::std::option::Option<bool>,
    _request_id: Option<String>,
}
impl StopQueryOutputBuilder {
    /// <p>This is true if the query was stopped by the <code>StopQuery</code> operation.</p>
    pub fn success(mut self, input: bool) -> Self {
        self.success = ::std::option::Option::Some(input);
        self
    }
    /// <p>This is true if the query was stopped by the <code>StopQuery</code> operation.</p>
    pub fn set_success(mut self, input: ::std::option::Option<bool>) -> Self {
        self.success = input;
        self
    }
    /// <p>This is true if the query was stopped by the <code>StopQuery</code> operation.</p>
    pub fn get_success(&self) -> &::std::option::Option<bool> {
        &self.success
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`StopQueryOutput`](crate::operation::stop_query::StopQueryOutput).
    pub fn build(self) -> crate::operation::stop_query::StopQueryOutput {
        crate::operation::stop_query::StopQueryOutput {
            success: self.success.unwrap_or_default(),
            _request_id: self._request_id,
        }
    }
}
