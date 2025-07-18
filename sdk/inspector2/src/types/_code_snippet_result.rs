// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains information on a code snippet retrieved by Amazon Inspector from a code vulnerability finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct CodeSnippetResult {
    /// <p>The ARN of a finding that the code snippet is associated with.</p>
    pub finding_arn: ::std::option::Option<::std::string::String>,
    /// <p>The line number of the first line of a code snippet.</p>
    pub start_line: ::std::option::Option<i32>,
    /// <p>The line number of the last line of a code snippet.</p>
    pub end_line: ::std::option::Option<i32>,
    /// <p>Contains information on the retrieved code snippet.</p>
    pub code_snippet: ::std::option::Option<::std::vec::Vec<crate::types::CodeLine>>,
    /// <p>Details of a suggested code fix.</p>
    pub suggested_fixes: ::std::option::Option<::std::vec::Vec<crate::types::SuggestedFix>>,
}
impl CodeSnippetResult {
    /// <p>The ARN of a finding that the code snippet is associated with.</p>
    pub fn finding_arn(&self) -> ::std::option::Option<&str> {
        self.finding_arn.as_deref()
    }
    /// <p>The line number of the first line of a code snippet.</p>
    pub fn start_line(&self) -> ::std::option::Option<i32> {
        self.start_line
    }
    /// <p>The line number of the last line of a code snippet.</p>
    pub fn end_line(&self) -> ::std::option::Option<i32> {
        self.end_line
    }
    /// <p>Contains information on the retrieved code snippet.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.code_snippet.is_none()`.
    pub fn code_snippet(&self) -> &[crate::types::CodeLine] {
        self.code_snippet.as_deref().unwrap_or_default()
    }
    /// <p>Details of a suggested code fix.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.suggested_fixes.is_none()`.
    pub fn suggested_fixes(&self) -> &[crate::types::SuggestedFix] {
        self.suggested_fixes.as_deref().unwrap_or_default()
    }
}
impl CodeSnippetResult {
    /// Creates a new builder-style object to manufacture [`CodeSnippetResult`](crate::types::CodeSnippetResult).
    pub fn builder() -> crate::types::builders::CodeSnippetResultBuilder {
        crate::types::builders::CodeSnippetResultBuilder::default()
    }
}

/// A builder for [`CodeSnippetResult`](crate::types::CodeSnippetResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct CodeSnippetResultBuilder {
    pub(crate) finding_arn: ::std::option::Option<::std::string::String>,
    pub(crate) start_line: ::std::option::Option<i32>,
    pub(crate) end_line: ::std::option::Option<i32>,
    pub(crate) code_snippet: ::std::option::Option<::std::vec::Vec<crate::types::CodeLine>>,
    pub(crate) suggested_fixes: ::std::option::Option<::std::vec::Vec<crate::types::SuggestedFix>>,
}
impl CodeSnippetResultBuilder {
    /// <p>The ARN of a finding that the code snippet is associated with.</p>
    pub fn finding_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.finding_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ARN of a finding that the code snippet is associated with.</p>
    pub fn set_finding_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.finding_arn = input;
        self
    }
    /// <p>The ARN of a finding that the code snippet is associated with.</p>
    pub fn get_finding_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.finding_arn
    }
    /// <p>The line number of the first line of a code snippet.</p>
    pub fn start_line(mut self, input: i32) -> Self {
        self.start_line = ::std::option::Option::Some(input);
        self
    }
    /// <p>The line number of the first line of a code snippet.</p>
    pub fn set_start_line(mut self, input: ::std::option::Option<i32>) -> Self {
        self.start_line = input;
        self
    }
    /// <p>The line number of the first line of a code snippet.</p>
    pub fn get_start_line(&self) -> &::std::option::Option<i32> {
        &self.start_line
    }
    /// <p>The line number of the last line of a code snippet.</p>
    pub fn end_line(mut self, input: i32) -> Self {
        self.end_line = ::std::option::Option::Some(input);
        self
    }
    /// <p>The line number of the last line of a code snippet.</p>
    pub fn set_end_line(mut self, input: ::std::option::Option<i32>) -> Self {
        self.end_line = input;
        self
    }
    /// <p>The line number of the last line of a code snippet.</p>
    pub fn get_end_line(&self) -> &::std::option::Option<i32> {
        &self.end_line
    }
    /// Appends an item to `code_snippet`.
    ///
    /// To override the contents of this collection use [`set_code_snippet`](Self::set_code_snippet).
    ///
    /// <p>Contains information on the retrieved code snippet.</p>
    pub fn code_snippet(mut self, input: crate::types::CodeLine) -> Self {
        let mut v = self.code_snippet.unwrap_or_default();
        v.push(input);
        self.code_snippet = ::std::option::Option::Some(v);
        self
    }
    /// <p>Contains information on the retrieved code snippet.</p>
    pub fn set_code_snippet(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CodeLine>>) -> Self {
        self.code_snippet = input;
        self
    }
    /// <p>Contains information on the retrieved code snippet.</p>
    pub fn get_code_snippet(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CodeLine>> {
        &self.code_snippet
    }
    /// Appends an item to `suggested_fixes`.
    ///
    /// To override the contents of this collection use [`set_suggested_fixes`](Self::set_suggested_fixes).
    ///
    /// <p>Details of a suggested code fix.</p>
    pub fn suggested_fixes(mut self, input: crate::types::SuggestedFix) -> Self {
        let mut v = self.suggested_fixes.unwrap_or_default();
        v.push(input);
        self.suggested_fixes = ::std::option::Option::Some(v);
        self
    }
    /// <p>Details of a suggested code fix.</p>
    pub fn set_suggested_fixes(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::SuggestedFix>>) -> Self {
        self.suggested_fixes = input;
        self
    }
    /// <p>Details of a suggested code fix.</p>
    pub fn get_suggested_fixes(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::SuggestedFix>> {
        &self.suggested_fixes
    }
    /// Consumes the builder and constructs a [`CodeSnippetResult`](crate::types::CodeSnippetResult).
    pub fn build(self) -> crate::types::CodeSnippetResult {
        crate::types::CodeSnippetResult {
            finding_arn: self.finding_arn,
            start_line: self.start_line,
            end_line: self.end_line,
            code_snippet: self.code_snippet,
            suggested_fixes: self.suggested_fixes,
        }
    }
}
