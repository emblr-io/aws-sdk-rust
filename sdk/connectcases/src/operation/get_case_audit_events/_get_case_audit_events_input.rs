// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetCaseAuditEventsInput {
    /// <p>A unique identifier of the case.</p>
    pub case_id: ::std::option::Option<::std::string::String>,
    /// <p>The unique identifier of the Cases domain.</p>
    pub domain_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of audit events to return. The current maximum supported value is 25. This is also the default when no other value is provided.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetCaseAuditEventsInput {
    /// <p>A unique identifier of the case.</p>
    pub fn case_id(&self) -> ::std::option::Option<&str> {
        self.case_id.as_deref()
    }
    /// <p>The unique identifier of the Cases domain.</p>
    pub fn domain_id(&self) -> ::std::option::Option<&str> {
        self.domain_id.as_deref()
    }
    /// <p>The maximum number of audit events to return. The current maximum supported value is 25. This is also the default when no other value is provided.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetCaseAuditEventsInput {
    /// Creates a new builder-style object to manufacture [`GetCaseAuditEventsInput`](crate::operation::get_case_audit_events::GetCaseAuditEventsInput).
    pub fn builder() -> crate::operation::get_case_audit_events::builders::GetCaseAuditEventsInputBuilder {
        crate::operation::get_case_audit_events::builders::GetCaseAuditEventsInputBuilder::default()
    }
}

/// A builder for [`GetCaseAuditEventsInput`](crate::operation::get_case_audit_events::GetCaseAuditEventsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetCaseAuditEventsInputBuilder {
    pub(crate) case_id: ::std::option::Option<::std::string::String>,
    pub(crate) domain_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetCaseAuditEventsInputBuilder {
    /// <p>A unique identifier of the case.</p>
    /// This field is required.
    pub fn case_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.case_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A unique identifier of the case.</p>
    pub fn set_case_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.case_id = input;
        self
    }
    /// <p>A unique identifier of the case.</p>
    pub fn get_case_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.case_id
    }
    /// <p>The unique identifier of the Cases domain.</p>
    /// This field is required.
    pub fn domain_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.domain_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the Cases domain.</p>
    pub fn set_domain_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.domain_id = input;
        self
    }
    /// <p>The unique identifier of the Cases domain.</p>
    pub fn get_domain_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.domain_id
    }
    /// <p>The maximum number of audit events to return. The current maximum supported value is 25. This is also the default when no other value is provided.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of audit events to return. The current maximum supported value is 25. This is also the default when no other value is provided.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of audit events to return. The current maximum supported value is 25. This is also the default when no other value is provided.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetCaseAuditEventsInput`](crate::operation::get_case_audit_events::GetCaseAuditEventsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_case_audit_events::GetCaseAuditEventsInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_case_audit_events::GetCaseAuditEventsInput {
            case_id: self.case_id,
            domain_id: self.domain_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
