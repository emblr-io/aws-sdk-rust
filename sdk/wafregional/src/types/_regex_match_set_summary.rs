// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <note>
/// <p>This is <b>AWS WAF Classic</b> documentation. For more information, see <a href="https://docs.aws.amazon.com/waf/latest/developerguide/classic-waf-chapter.html">AWS WAF Classic</a> in the developer guide.</p>
/// <p><b>For the latest version of AWS WAF</b>, use the AWS WAFV2 API and see the <a href="https://docs.aws.amazon.com/waf/latest/developerguide/waf-chapter.html">AWS WAF Developer Guide</a>. With the latest version, AWS WAF has a single set of endpoints for regional and global use.</p>
/// </note>
/// <p>Returned by <code>ListRegexMatchSets</code>. Each <code>RegexMatchSetSummary</code> object includes the <code>Name</code> and <code>RegexMatchSetId</code> for one <code>RegexMatchSet</code>.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct RegexMatchSetSummary {
    /// <p>The <code>RegexMatchSetId</code> for a <code>RegexMatchSet</code>. You use <code>RegexMatchSetId</code> to get information about a <code>RegexMatchSet</code>, update a <code>RegexMatchSet</code>, remove a <code>RegexMatchSet</code> from a <code>Rule</code>, and delete a <code>RegexMatchSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexMatchSet</code> and by <code>ListRegexMatchSets</code>.</p>
    pub regex_match_set_id: ::std::string::String,
    /// <p>A friendly name or description of the <code>RegexMatchSet</code>. You can't change <code>Name</code> after you create a <code>RegexMatchSet</code>.</p>
    pub name: ::std::string::String,
}
impl RegexMatchSetSummary {
    /// <p>The <code>RegexMatchSetId</code> for a <code>RegexMatchSet</code>. You use <code>RegexMatchSetId</code> to get information about a <code>RegexMatchSet</code>, update a <code>RegexMatchSet</code>, remove a <code>RegexMatchSet</code> from a <code>Rule</code>, and delete a <code>RegexMatchSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexMatchSet</code> and by <code>ListRegexMatchSets</code>.</p>
    pub fn regex_match_set_id(&self) -> &str {
        use std::ops::Deref;
        self.regex_match_set_id.deref()
    }
    /// <p>A friendly name or description of the <code>RegexMatchSet</code>. You can't change <code>Name</code> after you create a <code>RegexMatchSet</code>.</p>
    pub fn name(&self) -> &str {
        use std::ops::Deref;
        self.name.deref()
    }
}
impl RegexMatchSetSummary {
    /// Creates a new builder-style object to manufacture [`RegexMatchSetSummary`](crate::types::RegexMatchSetSummary).
    pub fn builder() -> crate::types::builders::RegexMatchSetSummaryBuilder {
        crate::types::builders::RegexMatchSetSummaryBuilder::default()
    }
}

/// A builder for [`RegexMatchSetSummary`](crate::types::RegexMatchSetSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct RegexMatchSetSummaryBuilder {
    pub(crate) regex_match_set_id: ::std::option::Option<::std::string::String>,
    pub(crate) name: ::std::option::Option<::std::string::String>,
}
impl RegexMatchSetSummaryBuilder {
    /// <p>The <code>RegexMatchSetId</code> for a <code>RegexMatchSet</code>. You use <code>RegexMatchSetId</code> to get information about a <code>RegexMatchSet</code>, update a <code>RegexMatchSet</code>, remove a <code>RegexMatchSet</code> from a <code>Rule</code>, and delete a <code>RegexMatchSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexMatchSet</code> and by <code>ListRegexMatchSets</code>.</p>
    /// This field is required.
    pub fn regex_match_set_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.regex_match_set_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <code>RegexMatchSetId</code> for a <code>RegexMatchSet</code>. You use <code>RegexMatchSetId</code> to get information about a <code>RegexMatchSet</code>, update a <code>RegexMatchSet</code>, remove a <code>RegexMatchSet</code> from a <code>Rule</code>, and delete a <code>RegexMatchSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexMatchSet</code> and by <code>ListRegexMatchSets</code>.</p>
    pub fn set_regex_match_set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.regex_match_set_id = input;
        self
    }
    /// <p>The <code>RegexMatchSetId</code> for a <code>RegexMatchSet</code>. You use <code>RegexMatchSetId</code> to get information about a <code>RegexMatchSet</code>, update a <code>RegexMatchSet</code>, remove a <code>RegexMatchSet</code> from a <code>Rule</code>, and delete a <code>RegexMatchSet</code> from AWS WAF.</p>
    /// <p><code>RegexMatchSetId</code> is returned by <code>CreateRegexMatchSet</code> and by <code>ListRegexMatchSets</code>.</p>
    pub fn get_regex_match_set_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.regex_match_set_id
    }
    /// <p>A friendly name or description of the <code>RegexMatchSet</code>. You can't change <code>Name</code> after you create a <code>RegexMatchSet</code>.</p>
    /// This field is required.
    pub fn name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A friendly name or description of the <code>RegexMatchSet</code>. You can't change <code>Name</code> after you create a <code>RegexMatchSet</code>.</p>
    pub fn set_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.name = input;
        self
    }
    /// <p>A friendly name or description of the <code>RegexMatchSet</code>. You can't change <code>Name</code> after you create a <code>RegexMatchSet</code>.</p>
    pub fn get_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.name
    }
    /// Consumes the builder and constructs a [`RegexMatchSetSummary`](crate::types::RegexMatchSetSummary).
    /// This method will fail if any of the following fields are not set:
    /// - [`regex_match_set_id`](crate::types::builders::RegexMatchSetSummaryBuilder::regex_match_set_id)
    /// - [`name`](crate::types::builders::RegexMatchSetSummaryBuilder::name)
    pub fn build(self) -> ::std::result::Result<crate::types::RegexMatchSetSummary, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::types::RegexMatchSetSummary {
            regex_match_set_id: self.regex_match_set_id.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "regex_match_set_id",
                    "regex_match_set_id was not specified but it is required when building RegexMatchSetSummary",
                )
            })?,
            name: self.name.ok_or_else(|| {
                ::aws_smithy_types::error::operation::BuildError::missing_field(
                    "name",
                    "name was not specified but it is required when building RegexMatchSetSummary",
                )
            })?,
        })
    }
}
