// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeExportConfigurationsInput {
    /// <p>A list of continuous export IDs to search for.</p>
    pub export_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    /// <p>A number between 1 and 100 specifying the maximum number of continuous export descriptions returned.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token from the previous call to describe-export-tasks.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeExportConfigurationsInput {
    /// <p>A list of continuous export IDs to search for.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.export_ids.is_none()`.
    pub fn export_ids(&self) -> &[::std::string::String] {
        self.export_ids.as_deref().unwrap_or_default()
    }
    /// <p>A number between 1 and 100 specifying the maximum number of continuous export descriptions returned.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token from the previous call to describe-export-tasks.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl DescribeExportConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeExportConfigurationsInput`](crate::operation::describe_export_configurations::DescribeExportConfigurationsInput).
    pub fn builder() -> crate::operation::describe_export_configurations::builders::DescribeExportConfigurationsInputBuilder {
        crate::operation::describe_export_configurations::builders::DescribeExportConfigurationsInputBuilder::default()
    }
}

/// A builder for [`DescribeExportConfigurationsInput`](crate::operation::describe_export_configurations::DescribeExportConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeExportConfigurationsInputBuilder {
    pub(crate) export_ids: ::std::option::Option<::std::vec::Vec<::std::string::String>>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl DescribeExportConfigurationsInputBuilder {
    /// Appends an item to `export_ids`.
    ///
    /// To override the contents of this collection use [`set_export_ids`](Self::set_export_ids).
    ///
    /// <p>A list of continuous export IDs to search for.</p>
    pub fn export_ids(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        let mut v = self.export_ids.unwrap_or_default();
        v.push(input.into());
        self.export_ids = ::std::option::Option::Some(v);
        self
    }
    /// <p>A list of continuous export IDs to search for.</p>
    pub fn set_export_ids(mut self, input: ::std::option::Option<::std::vec::Vec<::std::string::String>>) -> Self {
        self.export_ids = input;
        self
    }
    /// <p>A list of continuous export IDs to search for.</p>
    pub fn get_export_ids(&self) -> &::std::option::Option<::std::vec::Vec<::std::string::String>> {
        &self.export_ids
    }
    /// <p>A number between 1 and 100 specifying the maximum number of continuous export descriptions returned.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>A number between 1 and 100 specifying the maximum number of continuous export descriptions returned.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>A number between 1 and 100 specifying the maximum number of continuous export descriptions returned.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token from the previous call to describe-export-tasks.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token from the previous call to describe-export-tasks.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token from the previous call to describe-export-tasks.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`DescribeExportConfigurationsInput`](crate::operation::describe_export_configurations::DescribeExportConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::describe_export_configurations::DescribeExportConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::describe_export_configurations::DescribeExportConfigurationsInput {
            export_ids: self.export_ids,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
