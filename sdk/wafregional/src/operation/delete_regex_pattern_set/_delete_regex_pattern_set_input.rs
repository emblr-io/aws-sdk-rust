// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DeleteRegexPatternSetInput {
    /// <p>The <code>RegexPatternSetId</code> of the <code>RegexPatternSet</code> that you want to delete. <code>RegexPatternSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub regex_pattern_set_id: ::std::option::Option<::std::string::String>,
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub change_token: ::std::option::Option<::std::string::String>,
}
impl DeleteRegexPatternSetInput {
    /// <p>The <code>RegexPatternSetId</code> of the <code>RegexPatternSet</code> that you want to delete. <code>RegexPatternSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub fn regex_pattern_set_id(&self) -> ::std::option::Option<&str> {
        self.regex_pattern_set_id.as_deref()
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn change_token(&self) -> ::std::option::Option<&str> {
        self.change_token.as_deref()
    }
}
impl DeleteRegexPatternSetInput {
    /// Creates a new builder-style object to manufacture [`DeleteRegexPatternSetInput`](crate::operation::delete_regex_pattern_set::DeleteRegexPatternSetInput).
    pub fn builder() -> crate::operation::delete_regex_pattern_set::builders::DeleteRegexPatternSetInputBuilder {
        crate::operation::delete_regex_pattern_set::builders::DeleteRegexPatternSetInputBuilder::default()
    }
}

/// A builder for [`DeleteRegexPatternSetInput`](crate::operation::delete_regex_pattern_set::DeleteRegexPatternSetInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DeleteRegexPatternSetInputBuilder {
    pub(crate) regex_pattern_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) change_token: ::std::option::Option<::std::string::String>,
}
impl DeleteRegexPatternSetInputBuilder {
    /// <p>The <code>RegexPatternSetId</code> of the <code>RegexPatternSet</code> that you want to delete. <code>RegexPatternSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    /// This field is required.
    pub fn regex_pattern_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regex_pattern_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>RegexPatternSetId</code> of the <code>RegexPatternSet</code> that you want to delete. <code>RegexPatternSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub fn set_regex_pattern_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regex_pattern_set_id = input;
        self
    }
    /// <p>The <code>RegexPatternSetId</code> of the <code>RegexPatternSet</code> that you want to delete. <code>RegexPatternSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub fn get_regex_pattern_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.regex_pattern_set_id
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    /// This field is required.
    pub fn change_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.change_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn set_change_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.change_token = input;
        self
    }
    /// <p>The value returned by the most recent call to <code>GetChangeToken</code>.</p>
    pub fn get_change_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.change_token
    }
    /// Consumes the builder and constructs a [`DeleteRegexPatternSetInput`](crate::operation::delete_regex_pattern_set::DeleteRegexPatternSetInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::delete_regex_pattern_set::DeleteRegexPatternSetInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::delete_regex_pattern_set::DeleteRegexPatternSetInput {
            regex_pattern_set_id: self.regex_pattern_set_id,
            change_token: self.change_token,
        })
    }
}
