// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.

/// <p>Gets the VpcLinks collection under the caller's account in a selected region.</p>
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetVpcLinksInput {
    /// <p>The current pagination position in the paged result set.</p>
    pub position: ::std::option::Option<::std::string::String>,
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub limit: ::std::option::Option<i32>,
}
impl GetVpcLinksInput {
    /// <p>The current pagination position in the paged result set.</p>
    pub fn position(&self) -> ::std::option::Option<&str> {
        self.position.as_deref()
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn limit(&self) -> ::std::option::Option<i32> {
        self.limit
    }
}
impl GetVpcLinksInput {
    /// Creates a new builder-style object to manufacture [`GetVpcLinksInput`](crate::operation::get_vpc_links::GetVpcLinksInput).
    pub fn builder() -> crate::operation::get_vpc_links::builders::GetVpcLinksInputBuilder {
        crate::operation::get_vpc_links::builders::GetVpcLinksInputBuilder::default()
    }
}

/// A builder for [`GetVpcLinksInput`](crate::operation::get_vpc_links::GetVpcLinksInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetVpcLinksInputBuilder {
    pub(crate) position: ::std::option::Option<::std::string::String>,
    pub(crate) limit: ::std::option::Option<i32>,
}
impl GetVpcLinksInputBuilder {
    /// <p>The current pagination position in the paged result set.</p>
    pub fn position(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.position = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The current pagination position in the paged result set.</p>
    pub fn set_position(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.position = input;
        self
    }
    /// <p>The current pagination position in the paged result set.</p>
    pub fn get_position(&self) -> &::std::option::Option<::std::string::String> {
        &self.position
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn limit(mut self, input: i32) -> Self {
        self.limit = ::std::option::Option::Some(input);
        self
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn set_limit(mut self, input: ::std::option::Option<i32>) -> Self {
        self.limit = input;
        self
    }
    /// <p>The maximum number of returned results per page. The default value is 25 and the maximum value is 500.</p>
    pub fn get_limit(&self) -> &::std::option::Option<i32> {
        &self.limit
    }
    /// Consumes the builder and constructs a [`GetVpcLinksInput`](crate::operation::get_vpc_links::GetVpcLinksInput).
    pub fn build(self) -> ::std::result::Result<crate::operation::get_vpc_links::GetVpcLinksInput, ::aws_smithy_types::error::operation::BuildError> {
        ::std::result::Result::Ok(crate::operation::get_vpc_links::GetVpcLinksInput {
            position: self.position,
            limit: self.limit,
        })
    }
}
