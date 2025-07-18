// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Returns an array of <a href="https://docs.aws.amazon.com/awssupport/latest/APIReference/API_CaseDetails.html">CaseDetails</a> objects and a <code>nextToken</code> that defines a point for pagination in the result set.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct DescribeCasesOutput {
    /// <p>The details for the cases that match the request.</p>
    pub cases: ::std::option::Option<::std::vec::Vec<crate::types::CaseDetails>>,
    /// <p>A resumption point for pagination.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeCasesOutput {
    /// <p>The details for the cases that match the request.</p>
    ///
    /// If no value was sent for this field, a default will be set. If you want to determine if no value was sent, use `.cases.is_none()`.
    pub fn cases(&self) -> &[crate::types::CaseDetails] {
        self.cases.as_deref().unwrap_or_default()
    }
    /// <p>A resumption point for pagination.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ::aws_types::request_id::RequestId for DescribeCasesOutput {
    fn request_id(&self) -> Option<&str> {
        self._request_id.as_deref()
    }
}
impl DescribeCasesOutput {
    /// Creates a new builder-style object to manufacture [`DescribeCasesOutput`](crate::operation::describe_cases::DescribeCasesOutput).
    pub fn builder() -> crate::operation::describe_cases::builders::DescribeCasesOutputBuilder {
        crate::operation::describe_cases::builders::DescribeCasesOutputBuilder::default()
    }
}

/// A builder for [`DescribeCasesOutput`](crate::operation::describe_cases::DescribeCasesOutput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct DescribeCasesOutputBuilder {
    pub(crate) cases: ::std::option::Option<::std::vec::Vec<crate::types::CaseDetails>>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    _request_id: Option<String>,
}
impl DescribeCasesOutputBuilder {
    /// Appends an item to `cases`.
    ///
    /// To override the contents of this collection use [`set_cases`](Self::set_cases).
    ///
    /// <p>The details for the cases that match the request.</p>
    pub fn cases(mut self, input: crate::types::CaseDetails) -> Self {
        let mut v = self.cases.unwrap_or_default();
        v.push(input);
        self.cases = ::std::option::Option::Some(v);
        self
    }
    /// <p>The details for the cases that match the request.</p>
    pub fn set_cases(mut self, input: ::std::option::Option<::std::vec::Vec<crate::types::CaseDetails>>) -> Self {
        self.cases = input;
        self
    }
    /// <p>The details for the cases that match the request.</p>
    pub fn get_cases(&self) -> &::std::option::Option<::std::vec::Vec<crate::types::CaseDetails>> {
        &self.cases
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
    pub(crate) fn _request_id(mut self, request_id: impl Into<String>) -> Self {
        self._request_id = Some(request_id.into());
        self
    }

    pub(crate) fn _set_request_id(&mut self, request_id: Option<String>) -> &mut Self {
        self._request_id = request_id;
        self
    }
    /// Consumes the builder and constructs a [`DescribeCasesOutput`](crate::operation::describe_cases::DescribeCasesOutput).
    pub fn build(self) -> crate::operation::describe_cases::DescribeCasesOutput {
        crate::operation::describe_cases::DescribeCasesOutput {
            cases: self.cases,
            next_token: self.next_token,
            _request_id: self._request_id,
        }
    }
}
