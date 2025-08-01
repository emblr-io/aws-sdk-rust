// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Information about metrics summaries.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct MetricsSummary {
    /// <p>Lines of code metered in the code review. For the initial code review pull request and all subsequent revisions, this includes all lines of code in the files added to the pull request. In subsequent revisions, for files that already existed in the pull request, this includes only the changed lines of code. In both cases, this does not include non-code lines such as comments and import statements. For example, if you submit a pull request containing 5 files, each with 500 lines of code, and in a subsequent revision you added a new file with 200 lines of code, and also modified a total of 25 lines across the initial 5 files, <code>MeteredLinesOfCodeCount</code> includes the first 5 files (5 * 500 = 2,500 lines), the new file (200 lines) and the 25 changed lines of code for a total of 2,725 lines of code.</p>
    pub metered_lines_of_code_count: ::std::option::Option<i64>,
    /// <p>Lines of code suppressed in the code review based on the <code>excludeFiles</code> element in the <code>aws-codeguru-reviewer.yml</code> file. For full repository analyses, this number includes all lines of code in the files that are suppressed. For pull requests, this number only includes the <i>changed</i> lines of code that are suppressed. In both cases, this number does not include non-code lines such as comments and import statements. For example, if you initiate a full repository analysis on a repository containing 5 files, each file with 100 lines of code, and 2 files are listed as excluded in the <code>aws-codeguru-reviewer.yml</code> file, then <code>SuppressedLinesOfCodeCount</code> returns 200 (2 * 100) as the total number of lines of code suppressed. However, if you submit a pull request for the same repository, then <code>SuppressedLinesOfCodeCount</code> only includes the lines in the 2 files that changed. If only 1 of the 2 files changed in the pull request, then <code>SuppressedLinesOfCodeCount</code> returns 100 (1 * 100) as the total number of lines of code suppressed.</p>
    pub suppressed_lines_of_code_count: ::std::option::Option<i64>,
    /// <p>Total number of recommendations found in the code review.</p>
    pub findings_count: ::std::option::Option<i64>,
}
impl MetricsSummary {
    /// <p>Lines of code metered in the code review. For the initial code review pull request and all subsequent revisions, this includes all lines of code in the files added to the pull request. In subsequent revisions, for files that already existed in the pull request, this includes only the changed lines of code. In both cases, this does not include non-code lines such as comments and import statements. For example, if you submit a pull request containing 5 files, each with 500 lines of code, and in a subsequent revision you added a new file with 200 lines of code, and also modified a total of 25 lines across the initial 5 files, <code>MeteredLinesOfCodeCount</code> includes the first 5 files (5 * 500 = 2,500 lines), the new file (200 lines) and the 25 changed lines of code for a total of 2,725 lines of code.</p>
    pub fn metered_lines_of_code_count(&self) -> ::std::option::Option<i64> {
        self.metered_lines_of_code_count
    }
    /// <p>Lines of code suppressed in the code review based on the <code>excludeFiles</code> element in the <code>aws-codeguru-reviewer.yml</code> file. For full repository analyses, this number includes all lines of code in the files that are suppressed. For pull requests, this number only includes the <i>changed</i> lines of code that are suppressed. In both cases, this number does not include non-code lines such as comments and import statements. For example, if you initiate a full repository analysis on a repository containing 5 files, each file with 100 lines of code, and 2 files are listed as excluded in the <code>aws-codeguru-reviewer.yml</code> file, then <code>SuppressedLinesOfCodeCount</code> returns 200 (2 * 100) as the total number of lines of code suppressed. However, if you submit a pull request for the same repository, then <code>SuppressedLinesOfCodeCount</code> only includes the lines in the 2 files that changed. If only 1 of the 2 files changed in the pull request, then <code>SuppressedLinesOfCodeCount</code> returns 100 (1 * 100) as the total number of lines of code suppressed.</p>
    pub fn suppressed_lines_of_code_count(&self) -> ::std::option::Option<i64> {
        self.suppressed_lines_of_code_count
    }
    /// <p>Total number of recommendations found in the code review.</p>
    pub fn findings_count(&self) -> ::std::option::Option<i64> {
        self.findings_count
    }
}
impl MetricsSummary {
    /// Creates a new builder-style object to manufacture [`MetricsSummary`](crate::types::MetricsSummary).
    pub fn builder() -> crate::types::builders::MetricsSummaryBuilder {
        crate::types::builders::MetricsSummaryBuilder::default()
    }
}

/// A builder for [`MetricsSummary`](crate::types::MetricsSummary).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct MetricsSummaryBuilder {
    pub(crate) metered_lines_of_code_count: ::std::option::Option<i64>,
    pub(crate) suppressed_lines_of_code_count: ::std::option::Option<i64>,
    pub(crate) findings_count: ::std::option::Option<i64>,
}
impl MetricsSummaryBuilder {
    /// <p>Lines of code metered in the code review. For the initial code review pull request and all subsequent revisions, this includes all lines of code in the files added to the pull request. In subsequent revisions, for files that already existed in the pull request, this includes only the changed lines of code. In both cases, this does not include non-code lines such as comments and import statements. For example, if you submit a pull request containing 5 files, each with 500 lines of code, and in a subsequent revision you added a new file with 200 lines of code, and also modified a total of 25 lines across the initial 5 files, <code>MeteredLinesOfCodeCount</code> includes the first 5 files (5 * 500 = 2,500 lines), the new file (200 lines) and the 25 changed lines of code for a total of 2,725 lines of code.</p>
    pub fn metered_lines_of_code_count(mut self, input: i64) -> Self {
        self.metered_lines_of_code_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Lines of code metered in the code review. For the initial code review pull request and all subsequent revisions, this includes all lines of code in the files added to the pull request. In subsequent revisions, for files that already existed in the pull request, this includes only the changed lines of code. In both cases, this does not include non-code lines such as comments and import statements. For example, if you submit a pull request containing 5 files, each with 500 lines of code, and in a subsequent revision you added a new file with 200 lines of code, and also modified a total of 25 lines across the initial 5 files, <code>MeteredLinesOfCodeCount</code> includes the first 5 files (5 * 500 = 2,500 lines), the new file (200 lines) and the 25 changed lines of code for a total of 2,725 lines of code.</p>
    pub fn set_metered_lines_of_code_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.metered_lines_of_code_count = input;
        self
    }
    /// <p>Lines of code metered in the code review. For the initial code review pull request and all subsequent revisions, this includes all lines of code in the files added to the pull request. In subsequent revisions, for files that already existed in the pull request, this includes only the changed lines of code. In both cases, this does not include non-code lines such as comments and import statements. For example, if you submit a pull request containing 5 files, each with 500 lines of code, and in a subsequent revision you added a new file with 200 lines of code, and also modified a total of 25 lines across the initial 5 files, <code>MeteredLinesOfCodeCount</code> includes the first 5 files (5 * 500 = 2,500 lines), the new file (200 lines) and the 25 changed lines of code for a total of 2,725 lines of code.</p>
    pub fn get_metered_lines_of_code_count(&self) -> &::std::option::Option<i64> {
        &self.metered_lines_of_code_count
    }
    /// <p>Lines of code suppressed in the code review based on the <code>excludeFiles</code> element in the <code>aws-codeguru-reviewer.yml</code> file. For full repository analyses, this number includes all lines of code in the files that are suppressed. For pull requests, this number only includes the <i>changed</i> lines of code that are suppressed. In both cases, this number does not include non-code lines such as comments and import statements. For example, if you initiate a full repository analysis on a repository containing 5 files, each file with 100 lines of code, and 2 files are listed as excluded in the <code>aws-codeguru-reviewer.yml</code> file, then <code>SuppressedLinesOfCodeCount</code> returns 200 (2 * 100) as the total number of lines of code suppressed. However, if you submit a pull request for the same repository, then <code>SuppressedLinesOfCodeCount</code> only includes the lines in the 2 files that changed. If only 1 of the 2 files changed in the pull request, then <code>SuppressedLinesOfCodeCount</code> returns 100 (1 * 100) as the total number of lines of code suppressed.</p>
    pub fn suppressed_lines_of_code_count(mut self, input: i64) -> Self {
        self.suppressed_lines_of_code_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Lines of code suppressed in the code review based on the <code>excludeFiles</code> element in the <code>aws-codeguru-reviewer.yml</code> file. For full repository analyses, this number includes all lines of code in the files that are suppressed. For pull requests, this number only includes the <i>changed</i> lines of code that are suppressed. In both cases, this number does not include non-code lines such as comments and import statements. For example, if you initiate a full repository analysis on a repository containing 5 files, each file with 100 lines of code, and 2 files are listed as excluded in the <code>aws-codeguru-reviewer.yml</code> file, then <code>SuppressedLinesOfCodeCount</code> returns 200 (2 * 100) as the total number of lines of code suppressed. However, if you submit a pull request for the same repository, then <code>SuppressedLinesOfCodeCount</code> only includes the lines in the 2 files that changed. If only 1 of the 2 files changed in the pull request, then <code>SuppressedLinesOfCodeCount</code> returns 100 (1 * 100) as the total number of lines of code suppressed.</p>
    pub fn set_suppressed_lines_of_code_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.suppressed_lines_of_code_count = input;
        self
    }
    /// <p>Lines of code suppressed in the code review based on the <code>excludeFiles</code> element in the <code>aws-codeguru-reviewer.yml</code> file. For full repository analyses, this number includes all lines of code in the files that are suppressed. For pull requests, this number only includes the <i>changed</i> lines of code that are suppressed. In both cases, this number does not include non-code lines such as comments and import statements. For example, if you initiate a full repository analysis on a repository containing 5 files, each file with 100 lines of code, and 2 files are listed as excluded in the <code>aws-codeguru-reviewer.yml</code> file, then <code>SuppressedLinesOfCodeCount</code> returns 200 (2 * 100) as the total number of lines of code suppressed. However, if you submit a pull request for the same repository, then <code>SuppressedLinesOfCodeCount</code> only includes the lines in the 2 files that changed. If only 1 of the 2 files changed in the pull request, then <code>SuppressedLinesOfCodeCount</code> returns 100 (1 * 100) as the total number of lines of code suppressed.</p>
    pub fn get_suppressed_lines_of_code_count(&self) -> &::std::option::Option<i64> {
        &self.suppressed_lines_of_code_count
    }
    /// <p>Total number of recommendations found in the code review.</p>
    pub fn findings_count(mut self, input: i64) -> Self {
        self.findings_count = ::std::option::Option::Some(input);
        self
    }
    /// <p>Total number of recommendations found in the code review.</p>
    pub fn set_findings_count(mut self, input: ::std::option::Option<i64>) -> Self {
        self.findings_count = input;
        self
    }
    /// <p>Total number of recommendations found in the code review.</p>
    pub fn get_findings_count(&self) -> &::std::option::Option<i64> {
        &self.findings_count
    }
    /// Consumes the builder and constructs a [`MetricsSummary`](crate::types::MetricsSummary).
    pub fn build(self) -> crate::types::MetricsSummary {
        crate::types::MetricsSummary {
            metered_lines_of_code_count: self.metered_lines_of_code_count,
            suppressed_lines_of_code_count: self.suppressed_lines_of_code_count,
            findings_count: self.findings_count,
        }
    }
}
