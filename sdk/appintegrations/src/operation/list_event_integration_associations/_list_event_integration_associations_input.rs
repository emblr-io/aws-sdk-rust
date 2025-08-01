// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListEventIntegrationAssociationsInput {
    /// <p>The name of the event integration.</p>
    pub event_integration_name: ::std::option::Option<::std::string::String>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return per page.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListEventIntegrationAssociationsInput {
    /// <p>The name of the event integration.</p>
    pub fn event_integration_name(&self) -> ::std::option::Option<&str> {
        self.event_integration_name.as_deref()
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListEventIntegrationAssociationsInput {
    /// Creates a new builder-style object to manufacture [`ListEventIntegrationAssociationsInput`](crate::operation::list_event_integration_associations::ListEventIntegrationAssociationsInput).
    pub fn builder() -> crate::operation::list_event_integration_associations::builders::ListEventIntegrationAssociationsInputBuilder {
        crate::operation::list_event_integration_associations::builders::ListEventIntegrationAssociationsInputBuilder::default()
    }
}

/// A builder for [`ListEventIntegrationAssociationsInput`](crate::operation::list_event_integration_associations::ListEventIntegrationAssociationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListEventIntegrationAssociationsInputBuilder {
    pub(crate) event_integration_name: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListEventIntegrationAssociationsInputBuilder {
    /// <p>The name of the event integration.</p>
    /// This field is required.
    pub fn event_integration_name(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.event_integration_name = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The name of the event integration.</p>
    pub fn set_event_integration_name(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.event_integration_name = input;
        self
    }
    /// <p>The name of the event integration.</p>
    pub fn get_event_integration_name(&self) -> &::std::option::Option<::std::string::String> {
        &self.event_integration_name
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
    /// <p>The maximum number of results to return per page.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return per page.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListEventIntegrationAssociationsInput`](crate::operation::list_event_integration_associations::ListEventIntegrationAssociationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_event_integration_associations::ListEventIntegrationAssociationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(
            crate::operation::list_event_integration_associations::ListEventIntegrationAssociationsInput {
                event_integration_name: self.event_integration_name,
                next_token: self.next_token,
                max_results: self.max_results,
            },
        )
    }
}
