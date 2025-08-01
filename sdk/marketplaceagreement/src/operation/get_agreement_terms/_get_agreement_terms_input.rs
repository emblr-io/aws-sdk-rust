// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetAgreementTermsInput {
    /// <p>The unique identifier of the agreement.</p>
    pub agreement_id: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of agreements to return in the response.</p>
    pub max_results: ::std::option::Option<i32>,
    /// <p>A token to specify where to start pagination</p>
    pub next_token: ::std::option::Option<::std::string::String>,
}
impl GetAgreementTermsInput {
    /// <p>The unique identifier of the agreement.</p>
    pub fn agreement_id(&self) -> ::std::option::Option<&str> {
        self.agreement_id.as_deref()
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
    /// <p>A token to specify where to start pagination</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
}
impl GetAgreementTermsInput {
    /// Creates a new builder-style object to manufacture [`GetAgreementTermsInput`](crate::operation::get_agreement_terms::GetAgreementTermsInput).
    pub fn builder() -> crate::operation::get_agreement_terms::builders::GetAgreementTermsInputBuilder {
        crate::operation::get_agreement_terms::builders::GetAgreementTermsInputBuilder::default()
    }
}

/// A builder for [`GetAgreementTermsInput`](crate::operation::get_agreement_terms::GetAgreementTermsInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetAgreementTermsInputBuilder {
    pub(crate) agreement_id: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
}
impl GetAgreementTermsInputBuilder {
    /// <p>The unique identifier of the agreement.</p>
    /// This field is required.
    pub fn agreement_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.agreement_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The unique identifier of the agreement.</p>
    pub fn set_agreement_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.agreement_id = input;
        self
    }
    /// <p>The unique identifier of the agreement.</p>
    pub fn get_agreement_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.agreement_id
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of agreements to return in the response.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// <p>A token to specify where to start pagination</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>A token to specify where to start pagination</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>A token to specify where to start pagination</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// Consumes the builder and constructs a [`GetAgreementTermsInput`](crate::operation::get_agreement_terms::GetAgreementTermsInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_agreement_terms::GetAgreementTermsInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_agreement_terms::GetAgreementTermsInput {
            agreement_id: self.agreement_id,
            max_results: self.max_results,
            next_token: self.next_token,
        })
    }
}
