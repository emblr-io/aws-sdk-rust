// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListHoursOfOperationOverridesInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub instance_id: ::std::option::Option<::std::string::String>,
    /// <p>The identifier for the hours of operation</p>
    pub hours_of_operation_id: ::std::option::Option<::std::string::String>,
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return per page. The default MaxResult size is 100. Valid Range: Minimum value of 1. Maximum value of 1000.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListHoursOfOperationOverridesInput {
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn instance_id(&self) -> ::std::option::Option<&str> {
        self.instance_id.as_deref()
    }
    /// <p>The identifier for the hours of operation</p>
    pub fn hours_of_operation_id(&self) -> ::std::option::Option<&str> {
        self.hours_of_operation_id.as_deref()
    }
    /// <p>The token for the next set of results. Use the value returned in the previous response in the next request to retrieve the next set of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of results to return per page. The default MaxResult size is 100. Valid Range: Minimum value of 1. Maximum value of 1000.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListHoursOfOperationOverridesInput {
    /// Creates a new builder-style object to manufacture [`ListHoursOfOperationOverridesInput`](crate::operation::list_hours_of_operation_overrides::ListHoursOfOperationOverridesInput).
    pub fn builder() -> crate::operation::list_hours_of_operation_overrides::builders::ListHoursOfOperationOverridesInputBuilder {
        crate::operation::list_hours_of_operation_overrides::builders::ListHoursOfOperationOverridesInputBuilder::default()
    }
}

/// A builder for [`ListHoursOfOperationOverridesInput`](crate::operation::list_hours_of_operation_overrides::ListHoursOfOperationOverridesInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListHoursOfOperationOverridesInputBuilder {
    pub(crate) instance_id: ::std::option::Option<::std::string::String>,
    pub(crate) hours_of_operation_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListHoursOfOperationOverridesInputBuilder {
    /// <p>The identifier of the Amazon Connect instance.</p>
    /// This field is required.
    pub fn instance_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.instance_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn set_instance_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.instance_id = input;
        self
    }
    /// <p>The identifier of the Amazon Connect instance.</p>
    pub fn get_instance_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.instance_id
    }
    /// <p>The identifier for the hours of operation</p>
    /// This field is required.
    pub fn hours_of_operation_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.hours_of_operation_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The identifier for the hours of operation</p>
    pub fn set_hours_of_operation_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.hours_of_operation_id = input;
        self
    }
    /// <p>The identifier for the hours of operation</p>
    pub fn get_hours_of_operation_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.hours_of_operation_id
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
    /// <p>The maximum number of results to return per page. The default MaxResult size is 100. Valid Range: Minimum value of 1. Maximum value of 1000.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of results to return per page. The default MaxResult size is 100. Valid Range: Minimum value of 1. Maximum value of 1000.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of results to return per page. The default MaxResult size is 100. Valid Range: Minimum value of 1. Maximum value of 1000.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListHoursOfOperationOverridesInput`](crate::operation::list_hours_of_operation_overrides::ListHoursOfOperationOverridesInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_hours_of_operation_overrides::ListHoursOfOperationOverridesInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_hours_of_operation_overrides::ListHoursOfOperationOverridesInput {
            instance_id: self.instance_id,
            hours_of_operation_id: self.hours_of_operation_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
