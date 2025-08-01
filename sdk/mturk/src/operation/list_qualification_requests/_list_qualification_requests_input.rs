// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListQualificationRequestsInput {
    /// <p>The ID of the QualificationType.</p>
    pub qualification_type_id: ::std::option::Option<::std::string::String>,
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in a single call.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListQualificationRequestsInput {
    /// <p>The ID of the QualificationType.</p>
    pub fn qualification_type_id(&self) -> ::std::option::Option<&str> {
        self.qualification_type_id.as_deref()
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListQualificationRequestsInput {
    /// Creates a new builder-style object to manufacture [`ListQualificationRequestsInput`](crate::operation::list_qualification_requests::ListQualificationRequestsInput).
    pub fn builder() -> crate::operation::list_qualification_requests::builders::ListQualificationRequestsInputBuilder {
        crate::operation::list_qualification_requests::builders::ListQualificationRequestsInputBuilder::default()
    }
}

/// A builder for [`ListQualificationRequestsInput`](crate::operation::list_qualification_requests::ListQualificationRequestsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListQualificationRequestsInputBuilder {
    pub(crate) qualification_type_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListQualificationRequestsInputBuilder {
    /// <p>The ID of the QualificationType.</p>
    pub fn qualification_type_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.qualification_type_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the QualificationType.</p>
    pub fn set_qualification_type_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.qualification_type_id = input;
        self
    }
    /// <p>The ID of the QualificationType.</p>
    pub fn get_qualification_type_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.qualification_type_id
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>If the previous response was incomplete (because there is more data to retrieve), Amazon Mechanical Turk returns a pagination token in the response. You can use this pagination token to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListQualificationRequestsInput`](crate::operation::list_qualification_requests::ListQualificationRequestsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_qualification_requests::ListQualificationRequestsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_qualification_requests::ListQualificationRequestsInput {
            qualification_type_id: self.qualification_type_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
