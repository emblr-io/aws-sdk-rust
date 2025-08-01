// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Contains the details of the executed statement.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ExecuteStatementResult {
    /// <p>Contains the details of the first fetched page.</p>
    pub first_page: ::std::option::Option<crate::types::Page>,
    /// <p>Contains server-side performance information for the command.</p>
    pub timing_information: ::std::option::Option<crate::types::TimingInformation>,
    /// <p>Contains metrics about the number of I/O requests that were consumed.</p>
    pub consumed_ios: ::std::option::Option<crate::types::IoUsage>,
}
impl ExecuteStatementResult {
    /// <p>Contains the details of the first fetched page.</p>
    pub fn first_page(&self) -> ::std::option::Option<&crate::types::Page> {
        self.first_page.as_ref()
    }
    /// <p>Contains server-side performance information for the command.</p>
    pub fn timing_information(&self) -> ::std::option::Option<&crate::types::TimingInformation> {
        self.timing_information.as_ref()
    }
    /// <p>Contains metrics about the number of I/O requests that were consumed.</p>
    pub fn consumed_ios(&self) -> ::std::option::Option<&crate::types::IoUsage> {
        self.consumed_ios.as_ref()
    }
}
impl ExecuteStatementResult {
    /// Creates a new builder-style object to manufacture [`ExecuteStatementResult`](crate::types::ExecuteStatementResult).
    pub fn builder() -> crate::types::builders::ExecuteStatementResultBuilder {
        crate::types::builders::ExecuteStatementResultBuilder::default()
    }
}

/// A builder for [`ExecuteStatementResult`](crate::types::ExecuteStatementResult).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ExecuteStatementResultBuilder {
    pub(crate) first_page: ::std::option::Option<crate::types::Page>,
    pub(crate) timing_information: ::std::option::Option<crate::types::TimingInformation>,
    pub(crate) consumed_ios: ::std::option::Option<crate::types::IoUsage>,
}
impl ExecuteStatementResultBuilder {
    /// <p>Contains the details of the first fetched page.</p>
    pub fn first_page(mut self, input: crate::types::Page) -> Self {
        self.first_page = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains the details of the first fetched page.</p>
    pub fn set_first_page(mut self, input: ::std::option::Option<crate::types::Page>) -> Self {
        self.first_page = input;
        self
    }
    /// <p>Contains the details of the first fetched page.</p>
    pub fn get_first_page(&self) -> &::std::option::Option<crate::types::Page> {
        &self.first_page
    }
    /// <p>Contains server-side performance information for the command.</p>
    pub fn timing_information(mut self, input: crate::types::TimingInformation) -> Self {
        self.timing_information = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains server-side performance information for the command.</p>
    pub fn set_timing_information(mut self, input: ::std::option::Option<crate::types::TimingInformation>) -> Self {
        self.timing_information = input;
        self
    }
    /// <p>Contains server-side performance information for the command.</p>
    pub fn get_timing_information(&self) -> &::std::option::Option<crate::types::TimingInformation> {
        &self.timing_information
    }
    /// <p>Contains metrics about the number of I/O requests that were consumed.</p>
    pub fn consumed_ios(mut self, input: crate::types::IoUsage) -> Self {
        self.consumed_ios = ::std::option::Option::Some(input);
        self
    }
    /// <p>Contains metrics about the number of I/O requests that were consumed.</p>
    pub fn set_consumed_ios(mut self, input: ::std::option::Option<crate::types::IoUsage>) -> Self {
        self.consumed_ios = input;
        self
    }
    /// <p>Contains metrics about the number of I/O requests that were consumed.</p>
    pub fn get_consumed_ios(&self) -> &::std::option::Option<crate::types::IoUsage> {
        &self.consumed_ios
    }
    /// Consumes the builder and constructs a [`ExecuteStatementResult`](crate::types::ExecuteStatementResult).
    pub fn build(self) -> crate::types::ExecuteStatementResult {
        crate::types::ExecuteStatementResult {
            first_page: self.first_page,
            timing_information: self.timing_information,
            consumed_ios: self.consumed_ios,
        }
    }
}
