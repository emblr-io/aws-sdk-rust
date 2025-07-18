// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetRegexPatternSetOutput {
    /// <p>Information about the <code>RegexPatternSet</code> that you specified in the <code>GetRegexPatternSet</code> request, including the identifier of the pattern set and the regular expression patterns you want AWS WAF to search for.</p>
    pub regex_pattern_set: ::std::option::Option<crate::types::RegexPatternSet>,
    _request_id: Option<String>,
}
impl GetRegexPatternSetOutput {
    /// <p>Information about the <code>RegexPatternSet</code> that you specified in the <code>GetRegexPatternSet</code> request, including the identifier of the pattern set and the regular expression patterns you want AWS WAF to search for.</p>
    pub fn regex_pattern_set(&self) -> ::std::option::Option<&crate::types::RegexPatternSet> {
        self.regex_pattern_set.as_ref()
    }
}
impl ::aws_types::request_id::RequestId for GetRegexPatternSetOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl GetRegexPatternSetOutput {
    /// Creates a new builder-style object to manufacture [`GetRegexPatternSetOutput`](crate::operation::get_regex_pattern_set::GetRegexPatternSetOutput).
    pub fn builder() -> crate::operation::get_regex_pattern_set::builders::GetRegexPatternSetOutputBuilder {
        crate::operation::get_regex_pattern_set::builders::GetRegexPatternSetOutputBuilder::default()
    }
}

/// A builder for [`GetRegexPatternSetOutput`](crate::operation::get_regex_pattern_set::GetRegexPatternSetOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetRegexPatternSetOutputBuilder {
    pub(crate) regex_pattern_set: ::std::option::Option<crate::types::RegexPatternSet>,
    _request_id: Option<String>,
}
impl GetRegexPatternSetOutputBuilder {
    /// <p>Information about the <code>RegexPatternSet</code> that you specified in the <code>GetRegexPatternSet</code> request, including the identifier of the pattern set and the regular expression patterns you want AWS WAF to search for.</p>
    pub fn regex_pattern_set(mut self, input: crate::types::RegexPatternSet) -> Self {
        self.regex_pattern_set = ::std::option::Option::Some(input);
        self
    }
    /// <p>Information about the <code>RegexPatternSet</code> that you specified in the <code>GetRegexPatternSet</code> request, including the identifier of the pattern set and the regular expression patterns you want AWS WAF to search for.</p>
    pub fn set_regex_pattern_set(mut self, input: ::std::option::Option<crate::types::RegexPatternSet>) -> Self {
        self.regex_pattern_set = input;
        self
    }
    /// <p>Information about the <code>RegexPatternSet</code> that you specified in the <code>GetRegexPatternSet</code> request, including the identifier of the pattern set and the regular expression patterns you want AWS WAF to search for.</p>
    pub fn get_regex_pattern_set(&self) -> &::std::option::Option<crate::types::RegexPatternSet> {
        &self.regex_pattern_set
    }
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`GetRegexPatternSetOutput`](crate::operation::get_regex_pattern_set::GetRegexPatternSetOutput).
    pub fn build(self) -> crate::operation::get_regex_pattern_set::GetRegexPatternSetOutput {
        crate::operation::get_regex_pattern_set::GetRegexPatternSetOutput {
            regex_pattern_set: self.regex_pattern_set,
            _request_id: self._request_id,
        }
    }
}
