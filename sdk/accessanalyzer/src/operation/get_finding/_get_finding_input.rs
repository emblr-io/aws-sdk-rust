// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Retrieves a finding.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetFindingInput {
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#permission-resources">ARN of the analyzer</a> that generated the finding.</p>
    pub analyzer_arn: ::std::option::Option<::std::string::String>,
    /// <p>The ID of the finding to retrieve.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetFindingInput {
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#permission-resources">ARN of the analyzer</a> that generated the finding.</p>
    pub fn analyzer_arn(&self) -> ::std::option::Option<&str> {
        self.analyzer_arn.as_deref()
    }
    /// <p>The ID of the finding to retrieve.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetFindingInput {
    /// Creates a new builder-style object to manufacture [`GetFindingInput`](crate::operation::get_finding::GetFindingInput).
    pub fn builder() -> crate::operation::get_finding::builders::GetFindingInputBuilder {
        crate::operation::get_finding::builders::GetFindingInputBuilder::default()
    }
}

/// A builder for [`GetFindingInput`](crate::operation::get_finding::GetFindingInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetFindingInputBuilder {
    pub(crate) analyzer_arn: ::std::option::Option<::std::string::String>,
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetFindingInputBuilder {
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#permission-resources">ARN of the analyzer</a> that generated the finding.</p>
    /// This field is required.
    pub fn analyzer_arn(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.analyzer_arn = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#permission-resources">ARN of the analyzer</a> that generated the finding.</p>
    pub fn set_analyzer_arn(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.analyzer_arn = input;
        self
    }
    /// <p>The <a href="https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html#permission-resources">ARN of the analyzer</a> that generated the finding.</p>
    pub fn get_analyzer_arn(&self) -> &::std::option::Option<::std::string::String> {
        &self.analyzer_arn
    }
    /// <p>The ID of the finding to retrieve.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the finding to retrieve.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the finding to retrieve.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetFindingInput`](crate::operation::get_finding::GetFindingInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_finding::GetFindingInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_finding::GetFindingInput {
            analyzer_arn: self.analyzer_arn,
            id: self.id,
        })
    }
}
