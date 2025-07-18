// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRegexMatchSetOutput {
    /// <p>Information about the <code>RegexMatchSet</code> that you specified in the <code>GetRegexMatchSet</code> request. For more information, see <code>RegexMatchTuple</code>.</p>
    pub regex_match_set: ::std::option::Option<crate::types::RegexMatchSet>,
    _request_id: Option<String>,
}
impl GetRegexMatchSetOutput {
    /// <p>Information about the <code>RegexMatchSet</code> that you specified in the <code>GetRegexMatchSet</code> request. For more information, see <code>RegexMatchTuple</code>.</p>
    pub fn regex_match_set(&self) -> ::std::option::Option<&crate::types::RegexMatchSet> {
        self.regex_match_set.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRegexMatchSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRegexMatchSetOutput {
    /// Creates a new builder-style object to manufacture [`GetRegexMatchSetOutput`](crate::operation::get_regex_match_set::GetRegexMatchSetOutput).
    pub fn builder() -> crate::operation::get_regex_match_set::builders::GetRegexMatchSetOutputBuilder {
        crate::operation::get_regex_match_set::builders::GetRegexMatchSetOutputBuilder::default()
    }
}

/// A builder for [`GetRegexMatchSetOutput`](crate::operation::get_regex_match_set::GetRegexMatchSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRegexMatchSetOutputBuilder {
    pub(crate) regex_match_set: ::std::option::Option<crate::types::RegexMatchSet>,
    _request_id: Option<String>,
}
impl GetRegexMatchSetOutputBuilder {
    /// <p>Information about the <code>RegexMatchSet</code> that you specified in the <code>GetRegexMatchSet</code> request. For more information, see <code>RegexMatchTuple</code>.</p>
    pub fn regex_match_set(mut self, input: crate::types::RegexMatchSet) -> Self {
        self.regex_match_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the <code>RegexMatchSet</code> that you specified in the <code>GetRegexMatchSet</code> request. For more information, see <code>RegexMatchTuple</code>.</p>
    pub fn set_regex_match_set(mut self, input: ::std::option::Option<crate::types::RegexMatchSet>) -> Self {
        self.regex_match_set = input;
        self
    }
    /// <p>Information about the <code>RegexMatchSet</code> that you specified in the <code>GetRegexMatchSet</code> request. For more information, see <code>RegexMatchTuple</code>.</p>
    pub fn get_regex_match_set(&self) -> &::std::option::Option<crate::types::RegexMatchSet> {
        &self.regex_match_set
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRegexMatchSetOutput`](crate::operation::get_regex_match_set::GetRegexMatchSetOutput).
    pub fn build(self) -> crate::operation::get_regex_match_set::GetRegexMatchSetOutput {
        crate::operation::get_regex_match_set::GetRegexMatchSetOutput {
            regex_match_set: self.regex_match_set,
            _request_id: self._request_id,
        }
    }
}
