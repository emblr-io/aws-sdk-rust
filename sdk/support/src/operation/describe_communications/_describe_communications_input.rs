// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCommunicationsInput {
    /// <p>The support case ID requested or returned in the call. The case ID is an alphanumeric string formatted as shown in this example: case-<i>12345678910-2013-c4c1d2bf33c5cf47</i></p>
    pub case_id: ::std::option::Option<::std::string::String>,
    /// <p>The end date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub before_time: ::std::option::Option<::std::string::String>,
    /// <p>The start date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub after_time: ::std::option::Option<::std::string::String>,
    /// <p>A resumption point for pagination.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return before paginating.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl DescribeCommunicationsInput {
    /// <p>The support case ID requested or returned in the call. The case ID is an alphanumeric string formatted as shown in this example: case-<i>12345678910-2013-c4c1d2bf33c5cf47</i></p>
    pub fn case_id(&self) -> ::std::option::Option<&str> {
        self.case_id.as_deref()
    }
    /// <p>The end date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn before_time(&self) -> ::std::option::Option<&str> {
        self.before_time.as_deref()
    }
    /// <p>The start date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn after_time(&self) -> ::std::option::Option<&str> {
        self.after_time.as_deref()
    }
    /// <p>A resumption point for pagination.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return before paginating.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl DescribeCommunicationsInput {
    /// Creates a new builder-style object to manufacture [`DescribeCommunicationsInput`](crate::operation::describe_communications::DescribeCommunicationsInput).
    pub fn builder() -> crate::operation::describe_communications::builders::DescribeCommunicationsInputBuilder {
        crate::operation::describe_communications::builders::DescribeCommunicationsInputBuilder::default()
    }
}

/// A builder for [`DescribeCommunicationsInput`](crate::operation::describe_communications::DescribeCommunicationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCommunicationsInputBuilder {
    pub(crate) case_id: ::std::option::Option<::std::string::String>,
    pub(crate) before_time: ::std::option::Option<::std::string::String>,
    pub(crate) after_time: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl DescribeCommunicationsInputBuilder {
    /// <p>The support case ID requested or returned in the call. The case ID is an alphanumeric string formatted as shown in this example: case-<i>12345678910-2013-c4c1d2bf33c5cf47</i></p>
    /// This field is required.
    pub fn case_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.case_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The support case ID requested or returned in the call. The case ID is an alphanumeric string formatted as shown in this example: case-<i>12345678910-2013-c4c1d2bf33c5cf47</i></p>
    pub fn set_case_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.case_id = input;
        self
    }
    /// <p>The support case ID requested or returned in the call. The case ID is an alphanumeric string formatted as shown in this example: case-<i>12345678910-2013-c4c1d2bf33c5cf47</i></p>
    pub fn get_case_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.case_id
    }
    /// <p>The end date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn before_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.before_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The end date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn set_before_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.before_time = input;
        self
    }
    /// <p>The end date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn get_before_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.before_time
    }
    /// <p>The start date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn after_time(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.after_time = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The start date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn set_after_time(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.after_time = input;
        self
    }
    /// <p>The start date for a filtered date search on support case communications. Case communications are available for 12 months after creation.</p>
    pub fn get_after_time(&self) -> &::std::option::Option<::std::string::String> {
        &self.after_time
    }
    /// <p>A resumption point for pagination.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A resumption point for pagination.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A resumption point for pagination.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return before paginating.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return before paginating.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return before paginating.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`DescribeCommunicationsInput`](crate::operation::describe_communications::DescribeCommunicationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::describe_communications::DescribeCommunicationsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::describe_communications::DescribeCommunicationsInput {
            case_id: self.case_id,
            before_time: self.before_time,
            after_time: self.after_time,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
