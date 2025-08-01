// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct ListPagesByContactInput {
    /// <p>The Amazon Resource Name (ARN) of the contact you are retrieving engagements for.</p>
    pub contact_id: ::std::option::Option<::std::string::String>,
    /// <p>The pagination token to continue to the next page of results.</p>
    pub next_token: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of engagements to contact channels to list per page of results.</p>
    pub max_results: ::std::option::Option<i32>,
}
impl ListPagesByContactInput {
    /// <p>The Amazon Resource Name (ARN) of the contact you are retrieving engagements for.</p>
    pub fn contact_id(&self) -> ::std::option::Option<&str> {
        self.contact_id.as_deref()
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn next_token(&self) -> ::std::option::Option<&str> {
        self.next_token.as_deref()
    }
    /// <p>The maximum number of engagements to contact channels to list per page of results.</p>
    pub fn max_results(&self) -> ::std::option::Option<i32> {
        self.max_results
    }
}
impl ListPagesByContactInput {
    /// Creates a new builder-style object to manufacture [`ListPagesByContactInput`](crate::operation::list_pages_by_contact::ListPagesByContactInput).
    pub fn builder() -> crate::operation::list_pages_by_contact::builders::ListPagesByContactInputBuilder {
        crate::operation::list_pages_by_contact::builders::ListPagesByContactInputBuilder::default()
    }
}

/// A builder for [`ListPagesByContactInput`](crate::operation::list_pages_by_contact::ListPagesByContactInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct ListPagesByContactInputBuilder {
    pub(crate) contact_id: ::std::option::Option<::std::string::String>,
    pub(crate) next_token: ::std::option::Option<::std::string::String>,
    pub(crate) max_results: ::std::option::Option<i32>,
}
impl ListPagesByContactInputBuilder {
    /// <p>The Amazon Resource Name (ARN) of the contact you are retrieving engagements for.</p>
    /// This field is required.
    pub fn contact_id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.contact_id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the contact you are retrieving engagements for.</p>
    pub fn set_contact_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.contact_id = input;
        self
    }
    /// <p>The Amazon Resource Name (ARN) of the contact you are retrieving engagements for.</p>
    pub fn get_contact_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.contact_id
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn next_token(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.next_token = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn set_next_token(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.next_token = input;
        self
    }
    /// <p>The pagination token to continue to the next page of results.</p>
    pub fn get_next_token(&self) -> &::std::option::Option<::std::string::String> {
        &self.next_token
    }
    /// <p>The maximum number of engagements to contact channels to list per page of results.</p>
    pub fn max_results(mut self, input: i32) -> Self {
        self.max_results = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of engagements to contact channels to list per page of results.</p>
    pub fn set_max_results(mut self, input: ::std::option::Option<i32>) -> Self {
        self.max_results = input;
        self
    }
    /// <p>The maximum number of engagements to contact channels to list per page of results.</p>
    pub fn get_max_results(&self) -> &::std::option::Option<i32> {
        &self.max_results
    }
    /// Consumes the builder and constructs a [`ListPagesByContactInput`](crate::operation::list_pages_by_contact::ListPagesByContactInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::list_pages_by_contact::ListPagesByContactInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::list_pages_by_contact::ListPagesByContactInput {
            contact_id: self.contact_id,
            next_token: self.next_token,
            max_results: self.max_results,
        })
    }
}
