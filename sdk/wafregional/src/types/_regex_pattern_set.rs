// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This is <b>AWS WAF Classic</b> documentation. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html">AWS WAF Classic</a> in the developer guide.</p>
/// <p><b>For the latest version of AWS WAF</b>, use the AWS WAFV2 API and see the <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html">AWS WAF Developer Guide</a>. With the latest version, AWS WAF has a single set of endpoints for regional and global use.</p>
/// </note>
/// <p>The <code>RegexPatternSet</code> specifies the regular expression (regex) pattern that you want AWS WAF to search for, such as <code>B\[a@\]dB\[o0\]t</code>. You can then configure AWS WAF to reject those requests.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegexPatternSet {
    /// <p>The identifier for the <code>RegexPatternSet</code>. You use <code>RegexPatternSetId</code> to get information about a <code>RegexPatternSet</code>, update a <code>RegexPatternSet</code>, remove a <code>RegexPatternSet</code> from a <code>RegexMatchSet</code>, and delete a <code>RegexPatternSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub regex_pattern_set_id: ::std::string::String,
    /// <p>A friendly name or description of the <code>RegexPatternSet</code>. You can't change <code>Name</code> after you create a <code>RegexPatternSet</code>.</p>
    pub name: ::std::option::Option<::std::string::String>,
    /// <p>Specifies the regular expression (regex) patterns that you want AWS WAF to search for, such as <code>B\[a@\]dB\[o0\]t</code>.</p>
    pub regex_pattern_strings: ::std::vec::Vec<::std::string::String>,
}
impl RegexPatternSet {
    /// <p>The identifier for the <code>RegexPatternSet</code>. You use <code>RegexPatternSetId</code> to get information about a <code>RegexPatternSet</code>, update a <code>RegexPatternSet</code>, remove a <code>RegexPatternSet</code> from a <code>RegexMatchSet</code>, and delete a <code>RegexPatternSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub fn regex_pattern_set_id(&self) -> &str {
        use std::ops::Deref;
        self.regex_pattern_set_id.deref()
    }
    /// <p>A friendly name or description of the <code>RegexPatternSet</code>. You can't change <code>Name</code> after you create a <code>RegexPatternSet</code>.</p>
    pub fn name(&self) -> ::std::option::Option<&str> {
        self.name.as_deref()
    }
    /// <p>Specifies the regular expression (regex) patterns that you want AWS WAF to search for, such as <code>B\[a@\]dB\[o0\]t</code>.</p>
    pub fn regex_pattern_strings(&self) -> &[::std::string::String] {
        use std::ops::Deref;
        self.regex_pattern_strings.deref()
    }
}
impl RegexPatternSet {
    /// Creates a new builder-style object to manufacture [`RegexPatternSet`](crate::types::RegexPatternSet).
    pub fn builder() -> crate::types::builders::RegexPatternSetBuilder {
        crate::types::builders::RegexPatternSetBuilder::default()
    }
}

/// A builder for [`RegexPatternSet`](crate::types::RegexPatternSet).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegexPatternSetBuilder {
    pub(crate) regex_pattern_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
    pub(crate) regex_pattern_strings: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
}
impl RegexPatternSetBuilder {
    /// <p>The identifier for the <code>RegexPatternSet</code>. You use <code>RegexPatternSetId</code> to get information about a <code>RegexPatternSet</code>, update a <code>RegexPatternSet</code>, remove a <code>RegexPatternSet</code> from a <code>RegexMatchSet</code>, and delete a <code>RegexPatternSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    /// This field is required.
    pub fn regex_pattern_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regex_pattern_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the <code>RegexPatternSet</code>. You use <code>RegexPatternSetId</code> to get information about a <code>RegexPatternSet</code>, update a <code>RegexPatternSet</code>, remove a <code>RegexPatternSet</code> from a <code>RegexMatchSet</code>, and delete a <code>RegexPatternSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub fn set_regex_pattern_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regex_pattern_set_id = input;
        self
    }
    /// <p>The identifier for the <code>RegexPatternSet</code>. You use <code>RegexPatternSetId</code> to get information about a <code>RegexPatternSet</code>, update a <code>RegexPatternSet</code>, remove a <code>RegexPatternSet</code> from a <code>RegexMatchSet</code>, and delete a <code>RegexPatternSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexPatternSet</code> and by <code>ListRegexPatternSets</code>.</p>
    pub fn get_regex_pattern_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.regex_pattern_set_id
    }
    /// <p>A friendly name or description of the <code>RegexPatternSet</code>. You can't change <code>Name</code> after you create a <code>RegexPatternSet</code>.</p>
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly name or description of the <code>RegexPatternSet</code>. You can't change <code>Name</code> after you create a <code>RegexPatternSet</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A friendly name or description of the <code>RegexPatternSet</code>. You can't change <code>Name</code> after you create a <code>RegexPatternSet</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Appends an item to `regex_pattern_strings`.
    ///
    /// To override the contents of this collection use [`set_regex_pattern_strings`](Self::set_regex_pattern_strings).
    ///
    /// <p>Specifies the regular expression (regex) patterns that you want AWS WAF to search for, such as <code>B\[a@\]dB\[o0\]t</code>.</p>
    pub fn regex_pattern_strings(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.regex_pattern_strings.unwrap_or_default();
        v.push(input.into());
        self.regex_pattern_strings = ::std::option::Option::Some(v);
        self
    }
    /// <p>Specifies the regular expression (regex) patterns that you want AWS WAF to search for, such as <code>B\[a@\]dB\[o0\]t</code>.</p>
    pub fn set_regex_pattern_strings(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.regex_pattern_strings = input;
        self
    }
    /// <p>Specifies the regular expression (regex) patterns that you want AWS WAF to search for, such as <code>B\[a@\]dB\[o0\]t</code>.</p>
    pub fn get_regex_pattern_strings(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.regex_pattern_strings
    }
    /// Consumes the builder and constructs a [`RegexPatternSet`](crate::types::RegexPatternSet).
    /// This method will fail if any of the following fields are not set:
    /// - [`regex_pattern_set_id`](crate::types::builders::RegexPatternSetBuilder::regex_pattern_set_id)
    /// - [`regex_pattern_strings`](crate::types::builders::RegexPatternSetBuilder::regex_pattern_strings)
    pub fn build(self) -> ::std::result::Result<crate::types::RegexPatternSet, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RegexPatternSet {
            regex_pattern_set_id: self.regex_pattern_set_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "regex_pattern_set_id",
                    "regex_pattern_set_id was not specified but it is required when building RegexPatternSet",
                )
            })?,
            name: self.name,
            regex_pattern_strings: self.regex_pattern_strings.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "regex_pattern_strings",
                    "regex_pattern_strings was not specified but it is required when building RegexPatternSet",
                )
            })?,
        })
    }
}
