// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListAvailabilityConfigurationsInput {
    /// <p>The WorkMail organization for which the <code>AvailabilityConfiguration</code>'s will be listed.</p>
    pub organization_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of results to return in a single call.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>The token to use to retrieve the next page of results. The first call does not require a token.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl ListAvailabilityConfigurationsInput {
    /// <p>The WorkMail organization for which the <code>AvailabilityConfiguration</code>'s will be listed.</p>
    pub fn organization_id(&self) -> ::std::option::Option<&str> {
        self.organization_id.as_deref()
    }
    /// <p>The maximum number of results to return in a single call.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>The token to use to retrieve the next page of results. The first call does not require a token.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl ListAvailabilityConfigurationsInput {
    /// Creates a new builder-style object to manufacture [`ListAvailabilityConfigurationsInput`](crate::operation::list_availability_configurations::ListAvailabilityConfigurationsInput).
    pub fn builder() -> crate::operation::list_availability_configurations::builders::ListAvailabilityConfigurationsInputBuilder {
        crate::operation::list_availability_configurations::builders::ListAvailabilityConfigurationsInputBuilder::default()
    }
}

/// A builder for [`ListAvailabilityConfigurationsInput`](crate::operation::list_availability_configurations::ListAvailabilityConfigurationsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListAvailabilityConfigurationsInputBuilder {
    pub(crate) organization_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl ListAvailabilityConfigurationsInputBuilder {
    /// <p>The WorkMail organization for which the <code>AvailabilityConfiguration</code>'s will be listed.</p>
    /// This field is required.
    pub fn organization_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.organization_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The WorkMail organization for which the <code>AvailabilityConfiguration</code>'s will be listed.</p>
    pub fn set_organization_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.organization_id = input;
        self
    }
    /// <p>The WorkMail organization for which the <code>AvailabilityConfiguration</code>'s will be listed.</p>
    pub fn get_organization_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.organization_id
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
    /// <p>The token to use to retrieve the next page of results. The first call does not require a token.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The token to use to retrieve the next page of results. The first call does not require a token.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The token to use to retrieve the next page of results. The first call does not require a token.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`ListAvailabilityConfigurationsInput`](crate::operation::list_availability_configurations::ListAvailabilityConfigurationsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<
        crate::operation::list_availability_configurations::ListAvailabilityConfigurationsInput,
        ::aws_smithy_types::error::operation::BuildError,
    > {
        ::std::result::Result::Ok(crate::operation::list_availability_configurations::ListAvailabilityConfigurationsInput {
            organization_id: self.organization_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
