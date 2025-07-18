// Code generated by software.amazon.smithy.rust.codegen.smithy-rs. DO NOT EDIT.
#[allow(missing_docs)] // documentation missing in model
#[non_exhaustive]
#[cfg_attr(feature = "serde-serialize", derive(::serde::Serialize))]
#[cfg_attr(feature = "serde-deserialize", derive(::serde::Deserialize))]
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::fmt::Debug)]
pub struct GetOutpostResolverInput {
    /// <p>The ID of the Resolver on the Outpost.</p>
    pub id: ::std::option::Option<::std::string::String>,
}
impl GetOutpostResolverInput {
    /// <p>The ID of the Resolver on the Outpost.</p>
    pub fn id(&self) -> ::std::option::Option<&str> {
        self.id.as_deref()
    }
}
impl GetOutpostResolverInput {
    /// Creates a new builder-style object to manufacture [`GetOutpostResolverInput`](crate::operation::get_outpost_resolver::GetOutpostResolverInput).
    pub fn builder() -> crate::operation::get_outpost_resolver::builders::GetOutpostResolverInputBuilder {
        crate::operation::get_outpost_resolver::builders::GetOutpostResolverInputBuilder::default()
    }
}

/// A builder for [`GetOutpostResolverInput`](crate::operation::get_outpost_resolver::GetOutpostResolverInput).
#[derive(::std::clone::Clone, ::std::cmp::PartialEq, ::std::default::Default, ::std::fmt::Debug)]
#[non_exhaustive]
pub struct GetOutpostResolverInputBuilder {
    pub(crate) id: ::std::option::Option<::std::string::String>,
}
impl GetOutpostResolverInputBuilder {
    /// <p>The ID of the Resolver on the Outpost.</p>
    /// This field is required.
    pub fn id(mut self, input: impl ::std::convert::Into<::std::string::String>) -> Self {
        self.id = ::std::option::Option::Some(input.into());
        self
    }
    /// <p>The ID of the Resolver on the Outpost.</p>
    pub fn set_id(mut self, input: ::std::option::Option<::std::string::String>) -> Self {
        self.id = input;
        self
    }
    /// <p>The ID of the Resolver on the Outpost.</p>
    pub fn get_id(&self) -> &::std::option::Option<::std::string::String> {
        &self.id
    }
    /// Consumes the builder and constructs a [`GetOutpostResolverInput`](crate::operation::get_outpost_resolver::GetOutpostResolverInput).
    pub fn build(
        self,
    ) -> ::std::result::Result<crate::operation::get_outpost_resolver::GetOutpostResolverInput, ::aws_smithy_types::error::operation::BuildError>
    {
        ::std::result::Result::Ok(crate::operation::get_outpost_resolver::GetOutpostResolverInput { id: self.id })
    }
}
